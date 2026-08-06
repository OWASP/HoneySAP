# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Author:
#   Martin Gallo (@martingalloar)
#   Code contributed by SecureAuth to the OWASP CBAS project
#

# Standard imports
import os
import re
import struct
from socket import error
from random import SystemRandom
# External imports
from scapy.packet import Raw
from pysap.SAPRFC import (SAPRFC, SAPRFCDTStruct, SAPRFCEXTEND,
                          rfc_req_type_values, rfc_func_type_values,
                          rfc_monitor_cmd_values, cpic_padd)
from pysap.SAPNI import (SAPNIServerThreaded, SAPNIServerHandler, SAPNIClient)
from pysap.SAPNWRFC import (find_tlv_field_by_marker, find_tlv_field_by_padd,
                             decode_value, extract_rfc_params, extract_xml_data)
from pysap.utils.crypto.rfc import ab_descramble
# Custom imports
from honeysap.core.logger import Loggeable
from honeysap.core.service import BaseTCPService
from honeysap.services.gateway.rfcsi_data import get_ddif_body
from honeysap.services.gateway.rfm_catalog import load_rfm_catalog
from honeysap.services.gateway.ddic_catalog import load_ddic_catalog


# Full 4-byte CPIC field paddings from pysap.  In the login handshake the
# TLV sequence is fixed, so the full padd (prev_end + field_start) reliably
# matches.  Using .find() on 4 bytes is faster than scanning for 2-byte
# markers byte-by-byte.
CPIC_RFC_F_PADD = cpic_padd["cpic_RFC_f_padd"].encode("latin-1")
CPIC_PROGRAM_PADD = cpic_padd["cpic_program_padd"].encode("latin-1")
CPIC_USERNAME_PADD = cpic_padd["cpic_username1_padd"].encode("latin-1")
CPIC_CLI_NBR_PADD = cpic_padd["cpic_cli_nbr1_padd"].encode("latin-1")
CPIC_IP_PADD = cpic_padd["cpic_ip_padd"].encode("latin-1")
CPIC_HOSTNAME_PADD = cpic_padd["cpic_host_sid_inbr_padd"].encode("latin-1")
CPIC_DEST_PADD = cpic_padd["cpic_dest_padd"].encode("latin-1")

# 2-byte start-markers for login CPIC fields.
# The 4-byte cpic_padd values encode [prev_end(2)][curr_start(2)], so they
# only match when the preceding field is exactly the one that was captured.
# Field order varies across NWRFC SDK versions, so we use the last 2 bytes
# (the actual field-start marker) with the flexible marker scanner instead.
MARKER_PASSWORD  = b"\x01\x17"  # cpic_password (scrambled)
MARKER_USERNAME  = b"\x01\x11"  # cpic_username1 (SAP logon user)
MARKER_OS_USER   = b"\x00\x09"  # cpic_username2 (OS/client-side user)
MARKER_CLI_NBR   = b"\x01\x14"  # cpic_cli_nbr1
MARKER_IP        = b"\x00\x07"  # cpic_ip
MARKER_HOSTNAME  = b"\x00\x08"  # cpic_host_sid_inbr
MARKER_DEST      = b"\x00\x06"  # cpic_dest

def _descramble_rfc_password(raw_field):
    """Descramble an RFC password using SAP's ab_scramble algorithm.

    The password field layout is [4-byte LE seed][scrambled bytes]. Tries
    ASCII (direct-RFC / NUC mode) first, then UTF-16LE (GW / Unicode mode).

    Returns the plaintext password string, or the hex representation
    if descrambling fails.
    """
    if len(raw_field) < 5:
        return raw_field.hex()

    try:
        text = ab_descramble(raw_field, encoding="ascii")
        if text.isprintable():
            return text
    except (UnicodeDecodeError, ValueError):
        pass

    try:
        if (len(raw_field) - 4) % 2 == 0:
            text = ab_descramble(raw_field, encoding="utf-16-le")
            if text and text.isprintable():
                return text
    except (UnicodeDecodeError, ValueError):
        pass

    return raw_field.hex()


def _strip_field(val):
    """Strip padding from a bytes or str value, return str."""
    if isinstance(val, bytes):
        val = val.strip(b"\x00 ")
        return val.decode("utf-8", errors="replace")
    if isinstance(val, str):
        return val.strip("\x00 ")
    return str(val) if val is not None else None


# Pre-compiled regex for fallback UTF-16LE function name extraction.
_RE_UTF16LE_FUNCNAME = re.compile(rb"((?:[A-Z/][A-Z0-9_/]\x00){4,})")

# Monitor commands (GW_SEND_CMD) that indicate hostile intent.
_DANGEROUS_MONITOR_CMDS = frozenset({
    "SUICIDE", "DELETE_CONN", "CANCEL_CONN",
    "DISCONNECT", "DELETE_CLIENT", "DELETE_REMGW",
})

# SDK-internal function modules — logged at INFO level (infrastructure noise).
# Everything else is a business call and gets highlighted at WARNING level.
_INFRA_FUNCS = frozenset({
    "RFC_GET_FUNCTION_INTERFACE", "RFC_SYSTEM_INFO",
    "DDIF_FIELDINFO_GET", "RFC_PING",
})


def _make_conversation_id():
    """Generate an 8-digit numeric conversation ID like a real SAP gateway."""
    return "".join([str(SystemRandom().randint(0, 9)) for _ in range(8)])


def _tlv(prev_marker, marker, data):
    """Build one TLV entry: [prev_marker:2][marker:2][length:2][data]."""
    return struct.pack("!HHH", prev_marker, marker, len(data)) + data


# CPIC header bytes from a real SAP server login response.  These encode
# server capability flags and are constant across connections.
_CPIC_HEADER = bytes.fromhex(
    "01010008010101050401000301010103"
    "000400000e0b01030106000b04010003"
    "00030200000023"
)

# Gateway-to-gateway variant: byte[4]=0x05, byte[32]=0x01 (from A4H pcap).
_CPIC_HEADER_GW = (lambda h: bytes([h[i] if i not in (4, 32) else
                                    (0x05 if i == 4 else 0x01)
                                    for i in range(len(h))])
                   )(_CPIC_HEADER)

# GW function-response constants derived from A4H-A4H SM59 pcap capture.
# 0x5001 TLV payload (15 bytes): CPIC session-state block.
_GW_5001_DATA = bytes.fromhex("244803030041030023004020000045")
# 8-byte IEEE-754 double sent in _tlv(0x0130, 0x0667, ...) for GW responses.
_GW_0667_FLOAT = bytes.fromhex("0000000000804740")
# Constant 4-byte suffix appended after body_length in 8-byte trailer.
_GW_BODY_TRAILER_SUFFIX = b"\x00\x00\x6d\x60"
# 303-byte GW monitoring block (SAP gateway system-info exchange, field 0x0104).
# Captured from a real A4H gateway; SM59 does not validate the content.
_GW_MONITOR_BLOCK = bytes.fromhex(
    "100402000c000187680000044c00000bb8"
    "10040b0020ff7ffa0d78b737def6196e93"
    "25bf1597ef73feebdb51fd91ce3c214400"
    "0000001004040008001b00080012000810"
    "040d00100000001b000000820000002800"
    "0000821004160002000c10041900020000"
    "10041e0008000002e90000041710042500"
    "020001100409000338303010041d000231"
    "3210041f001557696e646f77732031302e"
    "30202832363130302920100420000f4945"
    "20392e31312e32363130302e3010042100"
    "084f6666696365203010042400080000053f"
    "000007e51004280008000004ec000007e2"
    "10042d0002000010041300450469c611e4"
    "2d1b0b8fe10000000a141e0f0169c611e9"
    "2d1b0b8fe10000000a141e0f0069c60fb6"
    "2d1b0b91e10000000a141e0f0069c6a669"
    "34be0bd4e10000000a141e4101"
)

# RFCSI structure field widths (SAP NW 7.52).  Total: 245 characters.
_RFCSI_FIELDS = [
    ("RFCPROTO", 3), ("RFCCHARTYP", 4), ("RFCINTTYP", 3), ("RFCFLOTYP", 3),
    ("RFCDEST", 32), ("RFCHOST", 8), ("RFCSYSID", 8), ("RFCDATABS", 8),
    ("RFCDBHOST", 32), ("RFCDBSYS", 10), ("RFCSAPRL", 4), ("RFCMACH", 5),
    ("RFCOPSYS", 10), ("RFCTZONE", 6), ("RFCDAYST", 1), ("RFCIPADDR", 15),
    ("RFCKERNRL", 4), ("RFCHOST2", 32), ("RFCSI_RESV", 12),
    ("RFCIPV6ADDR", 45),
]


# ---------------------------------------------------------------------------
# DFIES structure layout for NWRFC binary serialisation.
# Derived from the DFIES DDIC definition (Unicode-only, 1350 bytes per row).
# Each entry: dfies_field_name → (byte_offset, intlen, kind)
#   kind "c" = space-padded CHAR; kind "n" = zero-padded NUMC
# All fields are Unicode-encoded (UTF-16-LE).
# ---------------------------------------------------------------------------
_DFIES_LAYOUT = {
    "TABNAME":     (0,    60, "c"),
    "FIELDNAME":   (60,   60, "c"),
    "LANGU":       (120,   2, "c"),
    "POSITION":    (122,   8, "n"),
    "OFFSET":      (130,  12, "n"),
    "DOMNAME":     (142,  60, "c"),
    "ROLLNAME":    (202,  60, "c"),
    "CHECKTABLE":  (262,  60, "c"),
    "LENG":        (322,  12, "n"),
    "INTLEN":      (334,  12, "n"),
    "OUTPUTLEN":   (346,  12, "n"),
    "DECIMALS":    (358,  12, "n"),
    "DATATYPE":    (370,   8, "c"),
    "INTTYPE":     (378,   2, "c"),
    "REFTABLE":    (380,  60, "c"),
    "REFFIELD":    (440,  60, "c"),
    "PRECFIELD":   (500,  60, "c"),
    "AUTHORID":    (560,   6, "c"),
    "MEMORYID":    (566,  40, "c"),
    "LOGFLAG":     (606,   2, "c"),
    "MASK":        (608,  40, "c"),
    "MASKLEN":     (648,   8, "n"),
    "CONVEXIT":    (656,  10, "c"),
    "HEADLEN":     (666,   4, "n"),
    "SCRLEN1":     (670,   4, "n"),
    "SCRLEN2":     (674,   4, "n"),
    "SCRLEN3":     (678,   4, "n"),
    "FIELDTEXT":   (682, 120, "c"),
    "REPTEXT":     (802, 110, "c"),
    "SCRTEXT_S":   (912,  20, "c"),
    "SCRTEXT_M":   (932,  40, "c"),
    "SCRTEXT_L":   (972,  80, "c"),
    "KEYFLAG":    (1052,   2, "c"),
    "LOWERCASE":  (1054,   2, "c"),
    "MAC":        (1056,   2, "c"),
    "GENKEY":     (1058,   2, "c"),
    "NOFORKEY":   (1060,   2, "c"),
    "VALEXI":     (1062,   2, "c"),
    "NOAUTHCH":   (1064,   2, "c"),
    "SIGN_FLAG":  (1066,   2, "c"),   # DFIES.SIGN (numeric sign indicator)
    "DYNPFLD":    (1068,   2, "c"),
    "F4AVAILABL": (1070,   2, "c"),
    "COMPTYPE":   (1072,   2, "c"),
    "LFIELDNAME": (1074, 264, "c"),
    "LTRFLDDIS":  (1338,   2, "c"),
    "BIDICTRLC":  (1340,   2, "c"),
    "OUTPUTSTYLE":(1342,   4, "n"),
    "NOHISTORY":  (1346,   2, "c"),
    "AMPMFORMAT": (1348,   2, "c"),
}

# Initialised empty DFIES row: each field set to its "blank" value.
# CHAR ("c") → space (0x0020); NUMC ("n") → '0' (0x0030).
_DFIES_EMPTY_ROW = bytearray(1350)
for _fname, (_off, _ilen, _kind) in _DFIES_LAYOUT.items():
    _char = b"\x20\x00" if _kind == "c" else b"\x30\x00"
    _DFIES_EMPTY_ROW[_off:_off + _ilen] = _char * (_ilen // 2)
_DFIES_EMPTY_ROW = bytes(_DFIES_EMPTY_ROW)


def _build_dfies_row(field):
    """Build a 1350-byte DFIES row from a field dict (from ddic_catalog).

    field dict keys: tabname, fieldname, position, keyflag, datatype,
                     leng, outputlen, decimals, inttype, intlen, offset,
                     rollname, reptext
    """
    row = bytearray(_DFIES_EMPTY_ROW)

    def _wc(dfname, value):
        """Write a space-padded CHAR value."""
        off, intlen, _ = _DFIES_LAYOUT[dfname]
        chars = intlen // 2
        s = str(value or "")[:chars].ljust(chars)
        row[off:off + intlen] = s.encode("utf-16-le")

    def _wn(dfname, value):
        """Write a zero-padded NUMC value."""
        off, intlen, _ = _DFIES_LAYOUT[dfname]
        chars = intlen // 2
        s = str(int(value or 0)).zfill(chars)[:chars]
        row[off:off + intlen] = s.encode("utf-16-le")

    _wc("TABNAME",    field["tabname"])
    _wc("FIELDNAME",  field["fieldname"])
    _wn("POSITION",   field["position"])
    _wn("OFFSET",     field["offset"])
    _wn("LENG",       field["leng"])
    _wn("INTLEN",     field["intlen"])
    _wn("OUTPUTLEN",  field["outputlen"])
    _wn("DECIMALS",   field["decimals"])
    _wc("DATATYPE",   field["datatype"])
    _wc("INTTYPE",    field["inttype"])
    _wc("KEYFLAG",    field["keyflag"])
    _wc("ROLLNAME",   field["rollname"])
    _wc("REPTEXT",    field["reptext"])
    # TTYP (embedded internal table) fields in a structure:
    # COMPTYPE='L' = embedded internal table handle (not 'T' which means a
    # table TYPE's line field).  REFTABLE is for FK references, not line types;
    # the line type name is already in ROLLNAME.  Using 'T' or setting REFTABLE
    # causes the SDK to inline the table's line fields into the parent structure
    # layout → rc=20 overlap.  Confirmed from real SAP pcap analysis.
    if field.get("datatype") == "TTYP":
        _wc("COMPTYPE", "L")

    return bytes(row)


def _build_dfies_rows(fields, nuc_mode=False):
    """Build DFIES rows for *fields*, computing cumulative offsets.

    When *nuc_mode* is False (default, Unicode client / Communication
    Codepage 4103): the NWRFC SDK reads DFIES.INTLEN as UC byte length and
    halves CHAR-based values internally to derive NUC byte count.  Write UC
    lengths unchanged from the catalog.

    When *nuc_mode* is True (NUC client / Communication Codepage 1100): the
    NWRFC SDK reads DFIES.INTLEN directly as NUC byte count without halving.
    We write NUC lengths (halve CHAR-based UC values from the catalog) so the
    SDK's NUC sum matches X030L_WA.TABLEN and PARAMS.INTLENGTH.
    """
    rows = []
    offset = 0
    for f in fields:
        intlen_uc = int(f.get("intlen") or 0)
        # Skip zero-length fields (e.g. TTYP embedded-table placeholders).
        # DFIES rows with INTLEN=0 confuse the NWRFC SDK parser.
        if intlen_uc == 0:
            continue
        if nuc_mode and f.get("inttype", "") in _UC2_INTTYPES:
            intlen_wire = max(1, intlen_uc // 2)  # NUC value for CHAR-based
        else:
            intlen_wire = intlen_uc               # UC value (or non-CHAR type)
        f2 = dict(f)
        f2["intlen"] = intlen_wire  # value written into binary DFIES row
        f2["offset"] = offset       # cumulative offset in same units
        rows.append(_build_dfies_row(f2))
        offset += intlen_wire
    return rows


def _build_dfies_wa_row():
    """Build a blank DFIES_WA row (1350 bytes, all fields empty).

    On real SAP servers the DFIES_WA scalar export in the second
    DDIF_FIELDINFO_GET response is a fully blank DFIES row — all CHAR
    fields are spaces and all NUMC fields are zeros.  The SDK uses it as
    a signal that a structure descriptor follows (X030L_WA), NOT for the
    INTLEN value.  The authoritative NUC record length is in X030L_WA.TABLEN.
    """
    return _DFIES_EMPTY_ROW


def _build_x030l_wa_row(tabname, nuc_len):
    """Build a 416-byte X030L structure row for use as the DDIF X030L_WA export.

    X030L is the ABAP DDIC table/structure descriptor.  Real SAP servers send
    X030L_WA as a scalar export in the *second* DDIF_FIELDINFO_GET response.

    TABLEN (RAW4) is the authoritative NUC record length.  The SDK reads TABLEN
    from UC byte offset 164 in big-endian byte order.  Verified against a real
    SAP NW 7.52 pre-captured RFCSI blob: bytes[164:168] = 0x000000F5 (=245
    big-endian), matching X030L field layout from RFC trace addField lines.

    UC layout: 416 bytes total (SDK reads first 254 UC or 147 NUC bytes).
    """
    row = bytearray(416)
    # Initialise CHAR fields to UTF-16LE spaces (0x20 0x00 per char).
    # RAW fields remain zero.
    for off, size in (
        (0,   60),   # TABNAME   CHAR30
        (60,   2),   # DBASE     CHAR1
        (78,  28),   # CRSTAMP   CHAR14
        (106, 28),   # ABSTAMP   CHAR14
        (134, 28),   # DYSTAMP   CHAR14
        (172,  2),   # TABTYPE   CHAR1
        (174,  2),   # TABFORM   CHAR1
        (176, 60),   # REFNAME   CHAR30
        (242,  2),   # BUFSTATE  CHAR1
        (254, 34),   # DBSQLTIMESTMP CHAR17
    ):
        row[off:off + size] = b"\x20\x00" * (size // 2)
    # TABNAME (CHAR30 at UC offset 0, intlen 60)
    tn = tabname[:30].ljust(30)
    row[0:60] = tn.encode("utf-16-le")
    # TABLEN (RAW4) big-endian.  Must be written at TWO offsets:
    #
    #   NUC byte offset 91  — read by the SDK when UCLEN=0 (NUC/non-unicode server,
    #                         which is our mode).  The SDK uses the NUC layout of
    #                         X030L (147 bytes) and finds TABLEN at byte 91.
    #
    #   UC  byte offset 164 — read by the SDK when UCLEN=1 (Unicode server, as used
    #                         by real SAP NW; verified from pre-captured RFCSI blob:
    #                         bytes[164:168] = \x00\x00\x00\xf5 = 245 big-endian).
    #
    # Without the write at offset 91 (UCLEN=0 mode), the SDK reads the CRSTAMP
    # space bytes (0x20 0x00 ...) as TABLEN → non-zero garbage → rc=20.
    row[91:95]   = struct.pack(">I", nuc_len)   # NUC offset (UCLEN=0)
    row[164:168] = struct.pack(">I", nuc_len)   # UC  offset (UCLEN=1)
    return bytes(row)


# LINES_DESCR block: required by the NWRFC SDK between DFIES_WA and X030L_WA.
# Without this block the SDK cannot locate and parse X030L_WA.TABLEN, causing
# it to fall back to a wrong NUC length computation → rc=20.
# Captured verbatim from SAP NW 7.52; markers 0x3c02/0x3c05 are used for
# the <LINES_DESCR></LINES_DESCR> XML-style metadata tags (ASCII content).
# After the block, the current marker is 0x3c02 — use that as prev for X030L_WA.
_LINES_DESCR_CHUNK_SIZE = 1024   # bytes per inner TLV chunk (from pcap)
# After a LINES_DESCR block the active marker is 0x3c02.
_LINES_DESCR_TRAIL_MARKER = 0x3c02


def _build_lines_descr_block(xml_content=None):
    """Build the LINES_DESCR TLV block that precedes X030L_WA.

    When *xml_content* is None or empty the block contains only the bare
    ``<LINES_DESCR></LINES_DESCR>`` tags (empty, same as the original
    constant).  When *xml_content* is a non-empty ``bytes`` object it is
    split into 1024-byte inner TLVs (observed chunk size from real SAP).

    Block layout (all big-endian 2-byte ints):
        [0x0203][0x3c02][0x0000]              – empty 0x3c02 slot
        [0x3c02][0x3c05][0x000d]<LINES_DESCR>
        ([0x3c05][0x3c05][len]<chunk>)*       – content chunks, if any
        [0x3c05][0x3c05][0x000e]</LINES_DESCR>
        [0x3c05][0x3c02][0x0000]              – return to 0x3c02 zone
    """
    block  = struct.pack("!HHH", 0x0203, 0x3c02, 0)
    block += struct.pack("!HHH", 0x3c02, 0x3c05, 13) + b"<LINES_DESCR>"
    if xml_content:
        for i in range(0, len(xml_content), _LINES_DESCR_CHUNK_SIZE):
            chunk = xml_content[i:i + _LINES_DESCR_CHUNK_SIZE]
            block += struct.pack("!HHH", 0x3c05, 0x3c05, len(chunk)) + chunk
    block += struct.pack("!HHH", 0x3c05, 0x3c05, 14) + b"</LINES_DESCR>"
    block += struct.pack("!HHH", 0x3c05, 0x3c02, 0)
    return block


def _xml_field_item(tabname, fieldname, position, offset, leng, intlen, outputlen,
                    datatype, inttype, rollname="", comptype="E"):
    """Build one ``<item>…</item>`` XML block for LINES_DESCR field metadata.

    The tag list and format are derived from real SAP NW DDIF responses
    (pcap analysis).  Tags not relevant for SDK type-registration are left
    empty; they are still required because the SDK expects the full tag set.
    """
    def t(name, val=""):
        return f"<{name}>{val}</{name}>"

    return (
        "<item>"
        + t("TABNAME", tabname)
        + t("FIELDNAME", fieldname)
        + t("LANGU")
        + t("POSITION", f"{position:04d}")
        + t("OFFSET", f"{offset:06d}")
        + t("DOMNAME")
        + t("ROLLNAME", rollname)
        + t("CHECKTABLE")
        + t("LENG", f"{leng:06d}")
        + t("INTLEN", f"{intlen:06d}")
        + t("OUTPUTLEN", f"{outputlen:06d}")
        + t("DECIMALS", "000000")
        + t("DATATYPE", datatype)
        + t("INTTYPE", inttype)
        + t("REFTABLE")
        + t("REFFIELD")
        + t("PRECFIELD")
        + t("AUTHORID")
        + t("MEMORYID")
        + t("LOGFLAG")
        + t("MASK")
        + t("MASKLEN", "0000")
        + t("CONVEXIT")
        + t("HEADLEN", "00")
        + t("SCRLEN1", "00")
        + t("SCRLEN2", "00")
        + t("SCRLEN3", "00")
        + t("FIELDTEXT")
        + t("REPTEXT")
        + t("SCRTEXT_S")
        + t("SCRTEXT_M")
        + t("SCRTEXT_L")
        + t("KEYFLAG")
        + t("LOWERCASE")
        + t("MAC")
        + t("GENKEY")
        + t("NOFORKEY")
        + t("VALEXI")
        + t("NOAUTHCH")
        + t("SIGN")
        + t("DYNPFLD")
        + t("F4AVAILABL")
        + t("COMPTYPE", comptype)
        + t("LFIELDNAME", fieldname)
        + t("LTRFLDDIS")
        + t("BIDICTRLC")
        + t("OUTPUTSTYLE", "00")
        + t("NOHISTORY")
        + t("AMPMFORMAT")
        + "</item>"
    ).encode("ascii")


def _build_lines_descr_xml(tabname, fields, nuc_mode, catalog_fn=None):
    """Build the XML content for LINES_DESCR for *tabname*.

    Returns a ``bytes`` object with the XML, or ``None`` if the structure
    has no TTYP (nested internal-table) fields and therefore needs no
    LINES_DESCR content (the SDK is happy with an empty block in that case).

    *fields* — list of field dicts (same format as DFIES rows), sorted by
    position.  Must include TTYP fields (inttype='h').

    *nuc_mode* — True when the partner uses Communication Codepage 1100
    (NUC); INTLEN values in the XML are halved for CHAR-like types.

    *catalog_fn* — callable that takes a type name and returns its field
    list (used to look up line types for TTYP fields).
    """
    ttyp_fields = [f for f in fields if f.get("inttype") == "h"]
    if not ttyp_fields:
        # No nested TTYP fields — empty LINES_DESCR is sufficient.
        # The SDK either already knows this type (from a parent's LINES_DESCR)
        # or reads its field info from DFIES rows.
        return None

    # STRU: fields with named columns containing at least one TTYP handle.
    typekind = "STRU"

    # For table types the LINES_DESCR item 1 TYPENAME must be the line
    # structure (not the table type itself).  Real SAP sends TYPENAME=
    # <line_struct> so the SDK associates the table type with its row structure
    # and subsequently calls DDIF for the line structure by name.
    item1_typename = _TABLE_TYPE_LINETYPE.get(tabname, tabname)

    # Build field items for the structure itself.
    field_items = b""
    offset = 0
    for f in sorted(fields, key=lambda x: int(x.get("position") or 0)):
        inttype = f.get("inttype", "")
        intlen  = int(f.get("intlen") or 0)
        leng    = int(f.get("leng") or 0)
        if nuc_mode and inttype in _UC2_INTTYPES:
            xml_intlen = intlen // 2
        else:
            xml_intlen = intlen
        comptype = "L" if inttype == "h" else "E"
        field_items += _xml_field_item(
            tabname=item1_typename,
            fieldname=f.get("fieldname", ""),
            position=int(f.get("position") or 0),
            offset=offset,
            leng=leng,
            intlen=xml_intlen,
            outputlen=int(f.get("outputlen") or leng),
            datatype=f.get("datatype", ""),
            inttype=inttype,
            rollname=f.get("rollname", ""),
            comptype=comptype,
        )
        offset += xml_intlen

    # Only include the STRU item 1 when it names a DIFFERENT type (the line
    # structure of a table type, e.g. T_MODULE_GENERATE → S_MODULE_GENERATE).
    # When item1_typename == tabname the DFIES rows already describe the
    # structure; a redundant item 1 causes the SDK to see conflicting field
    # data and merge the nested TTYP line fields into the flat layout (→ rc=20).
    # Real SAP sends item 1 only for table types; structures get ONLY item 2+.
    if item1_typename != tabname:
        xml = (
            f"<item><TYPENAME>{item1_typename}</TYPENAME>"
            f"<TYPEKIND>{typekind}</TYPEKIND>"
            f"<FIELDS>{field_items.decode('ascii')}</FIELDS></item>"
        ).encode("ascii")
    else:
        xml = b""

    # Append nested-type items for each TTYP field.
    for tf in ttyp_fields:
        rollname = tf.get("rollname", "")
        if not rollname or catalog_fn is None:
            continue
        nested = catalog_fn(rollname)
        if not nested:
            continue
        nested_items = b""
        nested_offset = 0
        for nf in sorted(nested, key=lambda x: int(x.get("position") or 0)):
            n_inttype = nf.get("inttype", "")
            n_intlen  = int(nf.get("intlen") or 0)
            n_leng    = int(nf.get("leng") or 0)
            if nuc_mode and n_inttype in _UC2_INTTYPES:
                n_xml_intlen = n_intlen // 2
            else:
                n_xml_intlen = n_intlen
            nested_items += _xml_field_item(
                tabname=rollname,
                fieldname=nf.get("fieldname", ""),
                position=int(nf.get("position") or 0),
                offset=nested_offset,
                leng=n_leng,
                intlen=n_xml_intlen,
                outputlen=int(nf.get("outputlen") or n_leng),
                datatype=nf.get("datatype", ""),
                inttype=n_inttype,
                rollname=nf.get("rollname", ""),
                comptype="T",  # TTYP line field
            )
            nested_offset += n_xml_intlen
        xml += (
            f"<item><TYPENAME>{rollname}</TYPENAME>"
            f"<TYPEKIND>TTYP</TYPEKIND>"
            f"<FIELDS>{nested_items.decode('ascii')}</FIELDS></item>"
        ).encode("ascii")

    return xml or None


# ---------------------------------------------------------------------------
# Built-in DDIC entries for structures commonly needed but absent from the
# exported catalog (e.g. when the catalog was generated from a system where
# FUPARAREF stored incorrect TABNAME values).
#
# offset values are placeholder 0s — _build_dfies_rows recomputes them.
# ---------------------------------------------------------------------------
def _range_row(tabname, fieldname, pos, inttype, leng, intlen, rollname=""):
    """Helper to create one range-table field dict (offset computed later)."""
    return {
        "tabname":   tabname,
        "fieldname": fieldname,
        "position":  pos,
        "keyflag":   "",
        "datatype":  "CHAR",
        "leng":      leng,
        "outputlen": leng,
        "decimals":  0,
        "inttype":   inttype,
        "intlen":    intlen,
        "offset":    0,          # recomputed by _build_dfies_rows
        "rollname":  rollname,
        "reptext":   "",
    }


def _fld(tabname, fieldname, pos, datatype, inttype, leng, intlen, rollname=""):
    """General-purpose field dict helper (offset recomputed by _build_dfies_rows)."""
    return {
        "tabname":   tabname,
        "fieldname": fieldname,
        "position":  pos,
        "keyflag":   "",
        "datatype":  datatype,
        "leng":      leng,
        "outputlen": leng,
        "decimals":  0,
        "inttype":   inttype,
        "intlen":    intlen,
        "offset":    0,
        "rollname":  rollname,
        "reptext":   "",
    }


def _synthetic_ddic_fields(tabname, intlength):
    """Return DFIES field descriptors for types absent from the catalog.

    intlength is the raw A4HANA catalog value (unicode bytes, 2× non-unicode).
    We use CHAR ('C') fields so that the SDK computes uc = 2 * nuc for each
    field.  Because our RFCSI declares RFCCHARTYP=4103 (Unicode server), the
    SDK enforces uc >= 2*nuc for all structure fields; BYTE fields (uc==nuc)
    violate this and trigger "non-unicode length is too small".  CHAR fields
    satisfy the check since the SDK automatically doubles uc for CHAR types.

    intlen stored in the field dict is the UC byte count (intlength).
    _build_dfies_rows halves it for NUC-mode clients when INTTYPE is 'C'.
    nuc_total = intlength // 2 == RFCPARAM.INTLENGTH (NUC) == X030L.TABLEN.
    """
    uc_total = intlength if intlength > 0 else 2
    if uc_total % 2 != 0:
        uc_total += 1  # CHAR bytes must be even
    _MAX_CHAR_UC = 65534  # max CHAR field UC byte count (32767 chars × 2)

    fields = []
    remaining = uc_total
    pos = 1
    while remaining > 0:
        length = min(remaining, _MAX_CHAR_UC)
        fields.append(_fld(tabname, "DATA%d" % pos, pos,
                           "C", "C", length // 2, length))
        remaining -= length
        pos += 1
    return fields


# ---------------------------------------------------------------------------
# EXID type codes for which the unicode internal byte count is 2× the
# non-unicode byte count.  On a unicode SAP system (A4HANA) every CHAR-based
# type stores 2 bytes per logical character.
# ---------------------------------------------------------------------------
_UC2_EXIDS = frozenset({'C', 'N', 'D', 'T', 'Z'})

# INTTYPE codes (DFIES field) that are CHAR-based (unicode = 2 × non-unicode).
_UC2_INTTYPES = frozenset({'C', 'N', 'D', 'T', 'G', 'g'})

# Maximum number of flat DFIES rows to include in a single DDIF_FIELDINFO_GET
# response.  The NWRFC SDK cannot process responses with many DFIES rows
# (observed failure at 32 rows / ~44 KB body).  When more fields are present
# in the catalog the gateway falls back to a single synthetic RAW field so the
# SDK gets a valid (if opaque) type descriptor.
_MAX_DDIF_ROWS = 14


def _resolve_tabname(tabname, ddic_catalog):
    """Resolve a FUPARAREF tabname that may be a data-element reference.

    Some SAP systems (e.g. SolMan) store scalar parameter type info in
    FUPARAREF.STRUCTURE as "TYPENAME-TYPENAME" (same name on both sides of
    the hyphen) instead of the STRUCTURE field being empty and TYPE holding
    the name.  In that case the true catalog key is just the part before "-".

    Returns (resolved_tabname, is_scalar_deref) where is_scalar_deref=True
    means the tabname was a "X-X" data-element reference.
    """
    if not tabname or "-" not in tabname:
        return tabname, False
    parts = tabname.split("-", 1)
    base = parts[0]
    # Only normalise "ELEM-ELEM" patterns (both sides identical after trim)
    if parts[1].strip() != base.strip():
        return tabname, False
    if ddic_catalog and base in ddic_catalog:
        return base, True
    return tabname, False


def _nuc_intlength(exid, intlength, tabname, ddic_catalog):
    """Convert catalog unicode INTLENGTH to non-unicode byte count.

    The A4HANA RFC_GET_FUNCTION_INTERFACE response stores RFCPARAM.INTLENGTH
    in unicode bytes (2 per CHAR).  The NWRFC SDK wire protocol expects the
    non-unicode byte count.  This function converts accordingly so that the
    SDK check  sum(nucLen_from_DFIES) >= RFCPARAM.INTLENGTH  passes.

    For structure/table types ('u'/'h') the non-unicode total is computed
    field-by-field from the DDIC catalog when available; otherwise the
    catalog intlength is halved (NUC = UC/2) since synthetic RAW DFIES
    fields encode the NUC byte count directly.  PARAMS.INTLENGTH must
    match the NUC sum the SDK accumulates from DFIES rows.
    """
    if exid in _UC2_EXIDS:
        return intlength // 2
    elif exid in ('u', 'h'):
        # Resolve "ELEM-ELEM" data-element references (SolMan FUPARAREF quirk).
        resolved_tabname, _ = _resolve_tabname(tabname, ddic_catalog)
        # Check exported DDIC catalog first, then built-in hand-crafted entries.
        fields = (ddic_catalog.get(resolved_tabname) if ddic_catalog else None) \
                 or _BUILTIN_DDIC.get(resolved_tabname)
        if fields:
            total = 0
            for f in fields:
                finttype = f.get("inttype", "C")
                fintlen = int(f.get("intlen") or 0)
                # Skip zero-len and 'g' (STRG ref) — same filter as DFIES rows.
                if fintlen == 0 or finttype == "g":
                    continue
                total += fintlen // 2 if finttype in _UC2_INTTYPES else fintlen
            return total if total > 0 else max(1, intlength // 2)
        # Not in any catalog: synthesise CHAR fields (uc = 2*nuc satisfies the
        # SDK's uc >= 2*nuc check required for Unicode servers, RFCCHARTYP=4103).
        # DFIES.INTLEN stored as UC (intlength); halved to NUC on the wire.
        # PARAMS.INTLENGTH = NUC = intlength // 2.
        return max(1, intlength // 2)
    else:
        # INT4, INT2, INT1, FLOAT, PACKED, RAW, etc. — byte count unchanged.
        return intlength


_BUILTIN_DDIC = {
    # Range-of-username table (XUBNAME = CHAR 12 → unicode INTLEN 24 per field)
    # DFIES: unicode INTLEN values; nucLen = INTLEN/2 per CHAR field.
    # Sum nucLen: 1+2+12+12=27; _nuc_intlength(catalog_intlen=54) → 27 ✓
    "SUSR_T_RANGE_4_XUBNAME": [
        _range_row("SUSR_T_RANGE_4_XUBNAME", "SIGN",   1, "C",  1,  2),
        _range_row("SUSR_T_RANGE_4_XUBNAME", "OPTION", 2, "C",  2,  4),
        _range_row("SUSR_T_RANGE_4_XUBNAME", "LOW",    3, "C", 12, 24, "XUBNAME"),
        _range_row("SUSR_T_RANGE_4_XUBNAME", "HIGH",   4, "C", 12, 24, "XUBNAME"),
    ],
    # Time interval structure for audit log API
    # DFIES: unicode INTLEN values; nucLen = INTLEN/2 per D/T field.
    # Sum nucLen: 8+8+6+6=28; _nuc_intlength(catalog_intlen=56) → 28 ✓
    "RSAU_SEL_INTV": [
        _fld("RSAU_SEL_INTV", "DAT_FROM", 1, "DATS", "D", 8, 16),
        _fld("RSAU_SEL_INTV", "DAT_TO",   2, "DATS", "D", 8, 16),
        _fld("RSAU_SEL_INTV", "TIM_FROM", 3, "TIMS", "T", 6, 12),
        _fld("RSAU_SEL_INTV", "TIM_TO",   4, "TIMS", "T", 6, 12),
    ],
    # Line type for the /SLOAE/T_CODE nested table (TTYP) inside
    # /SLOAE/T_MODULE_GENERATE.  The table carries ABAP source code lines;
    # each row is a single CHAR(72) value (confirmed from working exploit
    # pcap: LENG=000072, INTLEN=000144 in UC DDIF call).  Empty fieldname
    # ("") is how ABAP exposes "table of scalar" line types to pyrfc.
    "/SLOAE/T_CODE": [
        _fld("/SLOAE/T_CODE", "", 1, "CHAR", "C", 72, 144),
    ],
    # Line structure for the /SLOAE/T_MODULE_GENERATE table type.
    # The ABAP DDIC exports T_MODULE_GENERATE's fields under its own TABNAME,
    # but the SDK also calls DDIF for S_MODULE_GENERATE (the actual row
    # structure) after learning its name from the LINES_DESCR XML in the
    # T_MODULE_GENERATE DDIF response.  We answer that call with the same 3
    # fields.  T_CODE is a TTYP handle (inttype='h', intlen=8 runtime pointer)
    # whose ROLLNAME tells the SDK to call DDIF for /SLOAE/T_CODE next.
    "/SLOAE/S_MODULE_GENERATE": [
        _fld("/SLOAE/S_MODULE_GENERATE", "MODULE_GUID", 1, "RAW",  "X", 16, 16),
        _fld("/SLOAE/S_MODULE_GENERATE", "REPORT_NAME", 2, "CHAR", "C", 40, 80,
             rollname="PROGNAME"),
        _fld("/SLOAE/S_MODULE_GENERATE", "T_CODE",      3, "TTYP", "h",  0,  8,
             rollname="/SLOAE/T_CODE"),
    ],
}


# Maps table-type TABNAME → line-structure TABNAME for types where the
# ABAP DDIC catalog exports the table type's fields under the table type's
# own name but the SDK expects the line structure name in LINES_DESCR item 1.
# Real SAP sends TYPENAME=<line_struct> (not the table type) in LINES_DESCR
# item 1 so the SDK correctly associates the table type with its row struct.
_TABLE_TYPE_LINETYPE = {
    "/SLOAE/T_MODULE_GENERATE": "/SLOAE/S_MODULE_GENERATE",
}

# TABNAMEs for which the DDIF response must contain 0 DFIES rows even though
# _BUILTIN_DDIC / ddic_catalog has field definitions for them.
#
# These are "table of scalar" line types whose field layout is already
# described in the parent structure's LINES_DESCR item 2.  If we return DFIES
# rows for these types the SDK re-registers them as STRU (overriding the TTYP
# registration from the parent's LINES_DESCR) and then tries to inline their
# fields into the parent structure → rc=20 offset overlap.
# Real SAP returns 0 DFIES rows + empty LINES_DESCR for these types.
_SUPPRESS_DFIES_TABNAMES = frozenset({
    "/SLOAE/T_CODE",
})


def _build_params_row(paramclass, parameter, tabname, fieldname, exid,
                      position, intlength, paramtext,
                      default="", optional=" "):
    """Build a single PARAMS table row (404 bytes).

    Matches the NWRFC SDK's hard-coded RFC_FUNINT structure layout exactly.
    The SDK reads fields at fixed UC byte offsets; any mismatch causes the
    wrong INTLENGTH to be read, leading to "non-unicode length is too small".

    Layout (UC byte offsets):
        PARAMCLASS (CHAR  1) →   2 bytes  @ offset   0
        PARAMETER  (CHAR 30) →  60 bytes  @ offset   2
        TABNAME    (CHAR 30) →  60 bytes  @ offset  62
        FIELDNAME  (CHAR 30) →  60 bytes  @ offset 122
        EXID       (CHAR  1) →   2 bytes  @ offset 182  (type code char, UTF-16LE)
        POSITION   (INT4)    →   4 bytes  @ offset 184
        OFFSET     (INT4)    →   4 bytes  @ offset 188
        INTLENGTH  (INT4)    →   4 bytes  @ offset 192
        DECIMALS   (INT4)    →   4 bytes  @ offset 196
        DEFAULT    (CHAR 21) →  42 bytes  @ offset 200
        PARAMTEXT  (CHAR 79) → 158 bytes  @ offset 242
        OPTIONAL   (CHAR  1) →   2 bytes  @ offset 400
        Total UC = 402 + 2 pad = 404.

    intlength - NUC byte length (computed via _nuc_intlength).  In NUC comm
                mode (Comm.CP 1100) the SDK reads RFC_FUNINT rows as 212-byte
                NUC structures; use _build_params_row_nuc() instead.
    """
    # CHAR fields: PARAMCLASS + PARAMETER + TABNAME + FIELDNAME (91 chars → 182 bytes)
    text = paramclass[0] if paramclass else " "
    text += parameter.ljust(30)[:30]
    text += tabname.ljust(30)[:30]
    text += fieldname.ljust(30)[:30]
    row = text.encode("utf-16-le")                                   # 182 bytes

    # EXID as CHAR(1) (2 bytes UTF-16LE), then POSITION, OFFSET, INTLENGTH,
    # DECIMALS — 2 + 4×INT4 = 18 bytes.  INTLENGTH lands at UC offset 192.
    exid_char = (exid[0] if exid else " ")
    row += exid_char.encode("utf-16-le")                             #   2 bytes EXID
    row += struct.pack("<IIII", position, 0, intlength, 0)           #  16 bytes

    # DEFAULT (21 chars), PARAMTEXT (79 chars), OPTIONAL (1 char), 2-byte pad
    row += default.ljust(21)[:21].encode("utf-16-le")               #  42 bytes
    row += paramtext.ljust(79)[:79].encode("utf-16-le")             # 158 bytes
    row += optional.ljust(1)[:1].encode("utf-16-le")                #   2 bytes
    row += b"\x00\x00"                                               #   2 bytes pad

    return row                                                        # total 404 bytes


def _build_params_row_nuc(paramclass, parameter, tabname, fieldname, exid,
                          position, intlength, paramtext,
                          default="", optional=" "):
    """Build a single PARAMS table row in NUC encoding (212 bytes).

    Used when the partner Communication Codepage is 1100 (NUC/Latin-1).
    In NUC mode the SDK reads RFC_FUNINT rows using 1-byte-per-CHAR encoding,
    so INTLENGTH lands at NUC offset 103 (not UC offset 194).

    Layout (NUC byte offsets):
        PARAMCLASS (CHAR  1) →   1 byte   @ offset   0
        PARAMETER  (CHAR 30) →  30 bytes  @ offset   1
        TABNAME    (CHAR 30) →  30 bytes  @ offset  31
        FIELDNAME  (CHAR 30) →  30 bytes  @ offset  61
        EXID       (CHAR  1) →   1 byte   @ offset  91  (type code char, Latin-1)
        POSITION   (INT4)    →   4 bytes  @ offset  92
        OFFSET     (INT4)    →   4 bytes  @ offset  96
        INTLENGTH  (INT4)    →   4 bytes  @ offset 100
        DECIMALS   (INT4)    →   4 bytes  @ offset 104
        DEFAULT    (CHAR 21) →  21 bytes  @ offset 108
        PARAMTEXT  (CHAR 79) →  79 bytes  @ offset 129
        OPTIONAL   (CHAR  1) →   1 byte   @ offset 208
        1-byte pad           →   1 byte   @ offset 209  (→ total 210; pad to 212)
        Total NUC = 212.
    """
    text = paramclass[0]
    text += parameter.ljust(30)[:30]
    text += tabname.ljust(30)[:30]
    text += fieldname.ljust(30)[:30]
    row = text.encode("latin-1")                                     # 91 bytes

    exid_char = (exid[0] if exid else " ")
    row += exid_char.encode("latin-1")                              #   1 byte  EXID
    row += struct.pack("<IIII", position, 0, intlength, 0)          #  16 bytes

    row += default.ljust(21)[:21].encode("latin-1")                 # 21 bytes
    row += paramtext.ljust(79)[:79].encode("latin-1")               # 79 bytes
    row += optional.ljust(1)[:1].encode("latin-1")                  #  1 byte
    row += b"\x00\x00\x00"                                          #  3 bytes pad

    return row                                                        # total 212 bytes


def _extract_session_id(raw):
    """Extract the 16-byte session ID from marker 0x0514 in an F_SAP_SEND."""
    pattern = b"\x05\x14\x00\x10"   # marker=0x0514, length=0x0010
    idx = raw.find(pattern)
    if idx >= 0 and idx + 20 <= len(raw):
        return raw[idx + 4:idx + 20]
    return os.urandom(16)


class SAPGatewayClient(Loggeable, SAPNIClient):

    registered = False
    username = None
    client_nbr = None
    conversation_id = None
    login_done = False  # True after the first F_SAP_SEND (login handshake)
    ddif_call_count = 0  # Tracks DDIF_FIELDINFO_GET call sequence (0-2)


class SAPGatewayServerHandler(Loggeable, SAPNIServerHandler):

    @property
    def hostname(self):
        return self.config.get("hostname", "sapnw702")

    @property
    def sid(self):
        return self.config.get("sid", "PRD")

    @property
    def instance_number(self):
        return self.config.get("instance_number", "00")

    @property
    def kernel_version(self):
        return self.config.get("kernel_version", "7200")

    @property
    def gateway_version(self):
        return self.config.get("gateway_version", "7200")

    @property
    def allow_monitor(self):
        return self.config.get("allow_monitor", True)

    @property
    def sap_release(self):
        return self.config.get("sap_release", "752")

    @property
    def db_system(self):
        return self.config.get("db_system", "HDB")

    @property
    def os_name(self):
        return self.config.get("os_name", "Linux")

    def __init__(self, request, client_address, server):
        self.config = server.config
        client_ip, client_port = client_address
        server_ip, server_port = server.server_address
        self.session = server.session_manager.get_session("gateway",
                                                          client_ip,
                                                          client_port,
                                                          server_ip,
                                                          server_port)
        # Codepage advertised by the client in the GW_NORMAL_CLIENT packet.
        # "1100" = non-Unicode (NUC) client; "4103" = Unicode client.
        # Defaults to "4103" (Unicode) so that catalog UC INTLEN values are
        # sent unchanged when we have not yet seen a GW_NORMAL_CLIENT.
        self._partner_codepage = "4103"
        # Set to True when the connection was established via the
        # GW_REMOTE_GATEWAY + F_ACCEPT_CONVERSATION gateway-to-gateway
        # handshake.  F_SAP_SEND packets from such connections use a
        # different header format (no codepage block at bytes 48-79) and
        # a different login indicator (raw[50]==0x7d instead of EBCDIC RFC).
        self._gw_connection = False
        # IP of the gateway peer that sent F_ACCEPT_CONVERSATION.  Set in
        # _handle_accept_conversation so that the back-connection thread can
        # connect to client_ip:3300 after the 80-byte ACK is received.
        self._gw_client_ip = None
        SAPNIServerHandler.__init__(self, request, client_address, server)

    # ------------------------------------------------------------------
    # Main dispatch
    # ------------------------------------------------------------------

    def handle_data(self):
        """Handles a received packet, dispatching by version/type."""
        self.session.add_event("Received packet", request=str(self.packet))

        # With base_cls=None the NI payload is not auto-decoded as SAPRFC.
        # We extract raw bytes from the SAPNI "payload" field directly.
        try:
            raw = bytes(self.packet.payload)
        except Exception:
            self.logger.debug("Failed to get payload bytes from %s",
                              str(self.client_address))
            return
        if len(raw) < 2:
            return

        try:
            version = raw[0]
            if version == 0x06:
                # APPC layer — RFC function call protocol
                func_type = raw[1]
                self._handle_appc(raw, func_type)
            else:
                # Gateway layer — connection management, monitor commands
                self._handle_gateway(raw, version)
        except Exception as exc:
            self.logger.error(
                "Unhandled exception in handle_data from %s: %s",
                str(self.client_address), exc, exc_info=True,
            )
            raise

    # ------------------------------------------------------------------
    # Gateway-level handlers (version != 0x06)
    # ------------------------------------------------------------------

    def _handle_gateway(self, raw, version):
        """Handle gateway-level request types."""
        if len(raw) < 2:
            return

        req_type = raw[1]
        req_name = rfc_req_type_values.get(req_type, "UNKNOWN(0x%02x)" % req_type)

        if req_type == 0x01:  # CHECK_GATEWAY
            self._handle_check_gateway(req_name)

        elif req_type == 0x03:  # GW_NORMAL_CLIENT
            self._handle_normal_client(raw, version, req_name)

        elif req_type == 0x09:  # GW_SEND_CMD
            self._handle_send_cmd(raw, req_name)

        elif req_type == 0x05:  # STOP_GATEWAY
            self.logger.warning("STOP_GATEWAY from %s", str(self.client_address))
            self.session.add_event("Dangerous gateway command attempted",
                                   data={"req_type": req_name})

        elif req_type == 0x04:  # GW_REMOTE_GATEWAY
            self._handle_remote_gateway(raw, req_name)

        elif req_type == 0x0b:  # GW_REGISTER_TP
            self.logger.debug("GW_REGISTER_TP from %s", str(self.client_address))
            self.session.add_event("TP registration request",
                                   data={"req_type": req_name})

        elif req_type == 0x0c:  # GW_UNREGISTER_TP
            self.logger.debug("GW_UNREGISTER_TP from %s", str(self.client_address))
            self.session.add_event("TP unregistration request",
                                   data={"req_type": req_name})

        else:
            self.logger.debug("Unhandled gateway request 0x%02x from %s",
                              req_type, str(self.client_address))
            self.session.add_event("Unhandled gateway request",
                                   data={"req_type": req_name,
                                         "req_type_id": req_type})

    def _handle_check_gateway(self, req_name):
        self.logger.debug("CHECK_GATEWAY from %s", str(self.client_address))
        self.session.add_event("Gateway check request",
                               data={"req_type": req_name})
        try:
            response = SAPRFC(version=3, req_type=0x01)
            self.request.send(response)
        except error:
            pass

    def _handle_remote_gateway(self, raw, req_name):
        """Handle GW_REMOTE_GATEWAY — gateway-to-gateway connection announcement.

        A SAP gateway sends this 60-byte packet when connecting to a remote
        gateway to establish a gateway-to-gateway link.  The layout is:

            raw[0]    version (0x02)
            raw[1]    req_type (0x04)
            raw[2:6]  gateway IP address (4 bytes, big-endian)
            raw[6:10] reserved (zeros)
            raw[10:18] service name (NUL-terminated, e.g. "sapdp00")
            raw[18:20] reserved
            raw[20:24] codepage ("4103" = Unicode)
            raw[24:30] reserved / sub-info (raw[29] = accept_info1)
            raw[30:50] hostname (20 bytes, space-padded)
            raw[50]   version/sub byte (0x06)
            raw[51]   accept_info (CODE_PAGE=0x10, NIPING=0x20)
            raw[52:60] trailing flags

        The expected response mirrors GW_NORMAL_CLIENT: echo the packet back
        with the CODE_PAGE (0x10) and NIPING (0x20) bits ORed into raw[51],
        and raw[29] incremented by one — as observed in live A4H↔A4H traces.
        After this handshake the connection carries normal APPC/RFC frames.
        """
        data = {"req_type": req_name}

        if len(raw) >= 18:
            try:
                ip = ".".join(str(b) for b in raw[2:6])
                if ip:
                    data["gateway_ip"] = ip
                service = raw[10:18].rstrip(b"\x00").decode("ascii",
                                                             errors="replace").strip()
                if service:
                    data["service"] = service
            except Exception:
                pass

        if len(raw) >= 24:
            try:
                cp = raw[20:24].decode("ascii").strip()
                if cp:
                    data["codepage"] = cp
                    self._partner_codepage = cp
            except (UnicodeDecodeError, AttributeError):
                pass

        if len(raw) >= 50:
            try:
                hostname = raw[30:50].rstrip(b" \x00").decode("ascii",
                                                               errors="replace")
                if hostname:
                    data["hostname"] = hostname
            except Exception:
                pass

        self.logger.debug("GW_REMOTE_GATEWAY from %s: ip=%s service=%s",
                          str(self.client_address),
                          data.get("gateway_ip"), data.get("service"))
        self.session.add_event("Remote gateway connection", data=data)

        # Echo back with CODE_PAGE (0x10) + NIPING (0x20) set in accept_info
        # (raw[51]) and sub-info bit set in raw[29] — same bit pattern observed
        # in A4H gateway-to-gateway traces.
        try:
            resp = bytearray(raw)
            if len(resp) > 29:
                resp[29] |= 0x01
            if len(resp) > 51:
                resp[51] |= 0x30
            self.request.send(Raw(bytes(resp)))
        except error:
            pass

    def _handle_accept_conversation(self, raw, func_name):
        """Handle F_ACCEPT_CONVERSATION / GW_NORMAL_CLIENT-v6.

        After the GW_REMOTE_GATEWAY handshake the connecting SAP gateway sends
        raw[0]=0x06, raw[1]=0x03 carrying the CPIC routing parameters plus
        connection stats and codepage info.

        The real target SAP gateway responds with F_SAP_SEND (raw[1]=0xcb),
        echoing back the CPIC routing block inside a modified header and
        stripping out the connection stats/codepage bytes.  Without this
        response the source SAP gateway hangs indefinitely waiting for a reply.

        Packet layout (confirmed from A4H gateway-to-gateway pcap traces):
          incoming bytes  0-39   fixed header (version, flags, conv state)
          incoming bytes 40-47   conv_id (8 ASCII digits, e.g. "01630698")
          incoming bytes 48-79   stats + codepage (stripped in response)
          incoming bytes 80+     CPIC routing strings (null-terminated)
                                 ends with "ENDOFSERVERINFO=1\\0"
                                 followed by "\\x01WASABAP\\0" (ignored)

        Response F_SAP_SEND layout:
          bytes  0-39   fixed F_SAP_SEND header (raw[1]=0xcb)
          bytes 40-47   conv_id (copied from incoming)
          bytes 48-79   29 zero bytes + \\x06\\x00\\x03
          bytes 80+     CPIC routing from incoming[80:ENDOFSERVERINFO+1]
          last 8 bytes  \\x00\\x00\\x00\\xee\\x00\\x00\\x7d\\x00
        """
        self.logger.debug("F_ACCEPT_CONVERSATION from %s", str(self.client_address))

        data = {"func_type": func_name}
        try:
            cpic_start = raw.find(b"CHECK_ONLY")
            if cpic_start > 0:
                cpic_raw = raw[cpic_start:]
                for part in cpic_raw.split(b"\x00"):
                    kv = part.split(b"=", 1)
                    if len(kv) == 2:
                        try:
                            data[kv[0].decode("ascii")] = kv[1].decode("ascii")
                        except UnicodeDecodeError:
                            pass
        except Exception:
            pass

        self._gw_connection = True
        self._gw_client_ip = self.client_address[0]

        # Detect whether this F_ACCEPT_CONVERSATION contains an embedded RFC
        # login (SM59 connection test) or is a pure gateway routing packet.
        # The EBCDIC "RFC" marker (0xd9 0xc6 0xc3) appears at the start of
        # the CPIC body in the SM59 case.
        ebcdic_rfc = b"\xd9\xc6\xc3"
        has_rfc_login = ebcdic_rfc in raw

        if has_rfc_login:
            # SM59 connection test: the packet carries a full RFC login
            # (credentials + RFC_PING invocation).  Extract the credentials
            # and respond with a proper login-success F_SAP_SEND so that SAP
            # proceeds to call RFC_GET_FUNCTION_INTERFACE / DDIF_FIELDINFO_GET.
            # Those exchanges complete the RFC_PING handshake; SAP then sends
            # the 80-byte ACK which triggers our NIPING back-connection.
            data["login_type"] = "sm59_rfc"
            self._extract_login_fields(raw, data)
            self.logger.info(
                "SM59 RFC login via gateway from %s: user=%s client=%s password=%s",
                str(self.client_address),
                data.get("username", "N/A"),
                data.get("client_number", "N/A"),
                data.get("password", "N/A"),
            )
            self.session.add_event("Gateway system info received", data=data)
            try:
                self._send_login_response(raw, data)
            except error:
                pass
        else:
            # Pure gateway routing packet (no embedded RFC login).
            # Echo the routing body back so the source gateway proceeds.
            self.session.add_event("Gateway system info received", data=data)
            _F_SAP_SEND_HDR = bytes([
                0x06, 0xcb, 0x02, 0x00, 0x03, 0xcf, 0x00, 0x02,  # bytes  0-7
                0x00, 0x00, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00,  # bytes  8-15
                0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,  # bytes 16-23
                0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x85, 0x0c,  # bytes 24-31
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # bytes 32-39
            ])
            _F_SAP_SEND_MID = b"\x00" * 29 + b"\x06\x00\x03"    # bytes 48-79
            _F_SAP_SEND_TAIL = b"\x00\x00\x00\xee\x00\x00\x7d\x00"
            try:
                conv_id = raw[40:48] if len(raw) >= 48 else b"\x00" * 8
                routing = b""
                if len(raw) > 80:
                    routing_raw = raw[80:]
                    marker = b"ENDOFSERVERINFO=1\x00"
                    idx = routing_raw.find(marker)
                    if idx >= 0:
                        routing = routing_raw[:idx + len(marker)]
                    else:
                        routing = routing_raw
                payload = _F_SAP_SEND_HDR + conv_id + _F_SAP_SEND_MID + routing + _F_SAP_SEND_TAIL
                self.request.send(Raw(bytes(payload)))
            except error:
                pass

    def _handle_normal_client(self, raw, version, req_name):
        """Handle GW_NORMAL_CLIENT — first packet in an RFC connection.

        Real SAP gateways echo the request back with additional accept_info
        flags (CODE_PAGE, NIPING).  We parse the request with pysap to log
        the fields and then build a response that matches the client version.
        """
        data = {"req_type": req_name}
        try:
            rfc = SAPRFC(raw)
            for field in ("lu", "tp", "service", "address", "conversation_id"):
                val = _strip_field(getattr(rfc, field, None))
                if val:
                    data[field] = val
        except Exception:
            pass

        self.logger.debug("GW_NORMAL_CLIENT from %s: lu=%s tp=%s service=%s",
                          str(self.client_address),
                          data.get("lu"), data.get("tp"), data.get("service"))
        self.session.add_event("Normal client connection", data=data)

        # Build response: echo the raw request but flip accept_info to add
        # CODE_PAGE (bit 4) and NIPING (bit 5).  In version 2 the
        # accept_info byte is at offset 41; in version 3 it is also at 41.
        #
        # Also override the codepage field (offset 20, 4 ASCII bytes) to
        # "4103" (Unicode).  The client sends "1100" (non-Unicode) by default;
        # if we echo it back unchanged the NWRFC SDK stores
        # Communication Codepage=1100 and treats every DFIES INTLEN as a NUC
        # byte count, causing the uc-len >= 2*nuc-len consistency check to
        # fail (rc=20) for any CHAR field whose INTLEN is already in UC bytes.
        # Record the client's codepage so DFIES INTLEN values can be sent in
        # the encoding the SDK expects.  The GW_NORMAL_CLIENT packet carries
        # the client's codepage as 4 ASCII bytes at offset 20.
        if len(raw) >= 24:
            try:
                cp = raw[20:24].decode("ascii").strip()
                if cp:
                    self._partner_codepage = cp
                    self.logger.debug("GW_NORMAL_CLIENT: partner_codepage=%s", cp)
            except (UnicodeDecodeError, AttributeError):
                pass

        try:
            resp = bytearray(raw)
            if len(resp) > 55:
                resp[55] = resp[55] | 0x10  # set CODE_PAGE bit in accept_info (offset 55)
                resp[20:24] = b"4103"       # advertise Unicode (4103) server codepage
            self.request.send(Raw(bytes(resp)))
        except error:
            pass

    def _handle_send_cmd(self, raw, req_name):
        """Handle GW_SEND_CMD — gateway monitor commands."""
        try:
            rfc = SAPRFC(raw)
            cmd = rfc.cmd
        except Exception:
            cmd = raw[2] if len(raw) > 2 else 0

        cmd_name = rfc_monitor_cmd_values.get(cmd, "UNKNOWN(0x%02x)" % cmd)
        self.logger.debug("GW_SEND_CMD from %s: cmd=%s",
                          str(self.client_address), cmd_name)
        self.session.add_event("Monitor command received",
                               data={"req_type": req_name,
                                     "cmd": cmd_name,
                                     "cmd_id": cmd})

        if cmd_name in _DANGEROUS_MONITOR_CMDS:
            self.logger.warning("Dangerous monitor command '%s' from %s",
                                cmd_name, str(self.client_address))
            self.session.add_event("Dangerous monitor command attempted",
                                   data={"cmd": cmd_name})

        if cmd == 0x01:  # NOOP — respond to keep client happy
            try:
                response = SAPRFC(version=3, req_type=0x09, cmd=0x01)
                self.request.send(response)
            except error:
                pass

    def _close_connection(self):
        """Close the client connection and signal the handler loop to stop.

        Sets the ``closed`` event (breaking the recv loop in
        SAPNIServerHandler.handle) and closes the underlying socket so the
        server sends a TCP FIN to the client.
        """
        self.logger.debug("Closing connection to %s", str(self.client_address))
        try:
            self.request.close()
        except error:
            pass
        self.close()

    # ------------------------------------------------------------------
    # APPC-level handlers (version == 0x06)
    # ------------------------------------------------------------------

    def _handle_appc(self, raw, func_type):
        """Dispatch APPC packets by function type."""
        func_name = rfc_func_type_values.get(func_type,
                                              "UNKNOWN(0x%02x)" % func_type)

        if func_type == 0x01:  # F_INITIALIZE_CONVERSATION
            self._handle_init_conversation(raw, func_name)

        elif func_type == 0x03:  # F_ACCEPT_CONVERSATION / GW_NORMAL_CLIENT-v6
            self._handle_accept_conversation(raw, func_name)

        elif func_type == 0x0f:  # F_SET_PARTNER_LU_NAME
            self.logger.debug("F_SET_PARTNER_LU_NAME from %s",
                              str(self.client_address))
            self.session.add_event("APPC set partner LU name",
                                   data={"func_type": func_name})
            # No response needed; client sends F_ALLOCATE next

        elif func_type == 0x05:  # F_ALLOCATE
            self._handle_allocate(raw, func_name)

        elif func_type == 0xcb:  # F_SAP_SEND
            self._handle_sap_send(raw, func_name)

        elif func_type == 0x0b:  # F_DEALLOCATE
            self.logger.debug("F_DEALLOCATE from %s", str(self.client_address))
            self.session.add_event("APPC deallocate",
                                   data={"func_type": func_name})
            self._close_connection()

        elif func_type == 0xce:  # F_SAP_PING
            self.logger.debug("F_SAP_PING from %s", str(self.client_address))
            self.session.add_event("APPC ping request",
                                   data={"func_type": func_name})
            try:
                response = SAPRFC(version=0x06, func_type=0xce, appc_rc=0x00)
                self.request.send(response)
            except error:
                pass

        elif func_type in (0xca, 0xc9):  # F_SAP_INIT / F_SAP_ALLOCATE (old style)
            self._handle_old_style_init(raw, func_type, func_name)

        elif func_type in (0xcf, 0xd0):  # F_SAP_REGTP / F_SAP_UNREGTP
            self.logger.debug("%s from %s", func_name, str(self.client_address))
            self.session.add_event("APPC TP registration",
                                   data={"func_type": func_name})

        elif func_type == 0xd5:  # F_SAP_CANCEL
            self.logger.debug("F_SAP_CANCEL from %s", str(self.client_address))
            self.session.add_event("APPC cancel request",
                                   data={"func_type": func_name})
            self._close_connection()

        else:
            self.logger.debug("Unhandled APPC 0x%02x from %s",
                              func_type, str(self.client_address))
            self.session.add_event("Unhandled APPC request",
                                   data={"func_type": func_name,
                                         "func_type_id": func_type})

    # -- F_INITIALIZE_CONVERSATION (0x01) --------------------------------

    def _handle_init_conversation(self, raw, func_name):
        """Handle F_INITIALIZE_CONVERSATION — extract user, destination, LU/TP
        from the sap_param (SAPRFCDTStruct) and sap_ext_header (SAPRFCEXTEND).

        Real servers echo the first 80 bytes of the request (48-byte APPC
        header + 32-byte SAPRFCEXTEND) with a generated conv_id filled in.
        """
        data = {"func_type": func_name}

        try:
            rfc = SAPRFC(raw)

            # Extract user and destination from parsed packet
            sap_param = getattr(rfc, "sap_param", None)
            if sap_param and isinstance(sap_param, SAPRFCDTStruct):
                for field in ("user", "long_lu", "long_tp"):
                    val = _strip_field(getattr(sap_param, field, None))
                    if val:
                        data[field] = val

                # The NWRFC SDK null-terminates the 12-byte 'user' field with
                # strlcpy semantics: for a 12-char OS username the null
                # overwrites the last character, so only 11 chars are
                # transmitted.  Flag this so log consumers know the value may
                # be one char short (use the SAP logon username from
                # F_SAP_SEND as the authoritative identity instead).
                user_val = data.get("user", "")
                if len(user_val) == 11:
                    data["os_user_truncated"] = True

                # Track user on connection
                if user_val and self.client_address in self.server.clients:
                    self.server.clients[self.client_address].username = user_val

            sap_ext = getattr(rfc, "sap_ext_header", None)
            if sap_ext and isinstance(sap_ext, SAPRFCEXTEND):
                for field in ("short_dest_name", "ncpic_lu", "ncpic_tp"):
                    val = _strip_field(getattr(sap_ext, field, None))
                    if val:
                        data[field] = val
        except Exception as e:
            self.logger.debug("Error parsing F_INITIALIZE_CONVERSATION: %s", e)

        user_display = data.get("user", "N/A")
        if data.get("os_user_truncated"):
            user_display += "? (truncated)"
        self.logger.info("RFC connection from %s: user=%s dest=%s lu=%s",
                         str(self.client_address),
                         user_display,
                         data.get("short_dest_name", "N/A"),
                         data.get("long_lu", "N/A"))
        self.session.add_event("APPC init conversation", data=data)

        # Respond: first 80 bytes of the request with conv_id filled in.
        # The real server sends 48-byte APPC header + 32-byte SAPRFCEXTEND
        # (short_dest_name, ncpic_lu, ncpic_tp, flags, code_page_tail).
        conv_id = _make_conversation_id()
        if self.client_address in self.server.clients:
            self.server.clients[self.client_address].conversation_id = conv_id

        data["conversation_id"] = conv_id

        try:
            if len(raw) >= 80:
                resp = bytearray(raw[:80])
            else:
                resp = bytearray(raw) + bytearray(80 - len(raw))
            # Write conv_id at offset 40-47
            resp[40:48] = conv_id.encode("ascii")
            # info4 (byte 21): real servers set to 0x06
            resp[21] = 0x06
            # code_page_tail (last 2 bytes of SAPRFCEXTEND): set to 0x0004
            resp[78:80] = b"\x00\x04"
            self.request.send(Raw(bytes(resp)))
        except error:
            pass

    # -- F_ALLOCATE (0x05) -----------------------------------------------

    def _handle_allocate(self, raw, func_name):
        """Handle F_ALLOCATE — accept the conversation allocation.

        Real servers respond with 80 bytes: 48-byte APPC header (with
        SYNC_CPIC_FUNCTION, GW_WITH_CODE_PAGE) + 32 bytes of codepage
        fields (mostly zeros, with the server instance port in codepage_v6).
        """
        self.logger.debug("F_ALLOCATE from %s", str(self.client_address))
        self.session.add_event("APPC allocate", data={"func_type": func_name})

        try:
            # Build 80-byte response from the request
            if len(raw) >= 80:
                resp = bytearray(raw[:80])
            else:
                resp = bytearray(raw) + bytearray(80 - len(raw))

            # info3 (byte 16): set GW_WITH_CODE_PAGE
            resp[16] = 0x01
            # info4 (byte 21): real server sets 0x02
            resp[21] = 0x02
            # info (bytes 29-30): set SYNC_CPIC_FUNCTION (0x0100 big-endian)
            resp[29] = 0x01
            resp[30] = 0x00
            # conv_id at bytes 40-47: keep from request (client already set it)
            # Write server instance port ("4103" format) into codepage_v6
            # at bytes 69-72 (offset 68 is codepage_v6 start, +1 for leading 0)
            svc_id = "41%s" % self.instance_number  # e.g. "4100"
            resp[69:69 + len(svc_id)] = svc_id.encode("ascii")
            # Clear the ffff at bytes 76-77 (old request padding)
            resp[76:78] = b"\x00\x00"
            # code_page_tail at byte 79
            resp[79] = 0x04

            self.request.send(Raw(bytes(resp)))
        except error:
            pass

    # -- F_SAP_SEND (0xcb) — the main RFC data exchange ------------------

    def _handle_sap_send(self, raw, func_name):
        """Handle F_SAP_SEND — extract function module name and credentials.

        pysap's SAPRFC class cannot parse F_SAP_SEND bodies due to
        conditional field issues, so we extract fields from the raw bytes.
        The APPC header is the first 48 bytes; after conv_id (bytes 40-47)
        the body contains CPIC-serialized RFC data.

        The first F_SAP_SEND in a connection is always a login handshake
        carrying credentials and the "RFCPING" marker function.  The actual
        RFC function module name arrives in subsequent F_SAP_SEND packets.
        """
        data = {"func_type": func_name}

        # Extract conv_id from APPC header
        if len(raw) >= 48:
            conv_id = raw[40:48].decode("ascii", errors="replace").strip("\x00 ")
            if conv_id:
                data["conversation_id"] = conv_id

        # Determine whether this is the login handshake (first F_SAP_SEND)
        # or an actual RFC function call.
        #
        # Direct NWRFC clients signal the login with an EBCDIC "RFC" marker
        # (0xD9 0xC6 0xC3) near the start of the body.
        #
        # Gateway-to-gateway connections (_gw_connection=True) use a different
        # format: the login F_SAP_SEND has raw[50] == 0x7d (observed in every
        # A4H gateway-to-gateway pcap trace).  There is no EBCDIC RFC marker.
        ebcdic_rfc = b"\xd9\xc6\xc3"  # EBCDIC for "RFC"
        if self._gw_connection:
            # Gateway-to-gateway login has raw[50]==0x7d (routing-block marker).
            data["gw_bytes48_56"] = (raw[48:56].hex() if len(raw) >= 56 else raw[48:].hex())
            data["gw_pktlen"] = len(raw)
            if len(raw) == 80 and self._gw_client_ip:
                # 80-byte header-only F_SAP_SEND = gateway "ACK" after our
                # F_SAP_SEND response.  The SAP is now waiting for us to
                # open a back-connection to client_ip:3300.  Don't respond
                # on this channel — just spawn the back-connection thread.
                self.session.add_event("Gateway ACK received, initiating back-connection",
                                       data=data)
                self._initiate_back_connection(self._gw_client_ip)
                return
            elif self.server.clients.get(self.client_address):
                # Client already logged in — this is a post-login RFC call
                # (e.g. RFC_PING from SM59 connection test).  Route to RFC
                # dispatch below; don't re-send login response.
                is_login = False
            elif len(raw) > 50 and raw[50] == 0x7d:
                is_login = True
            else:
                # Pre-login Diag-type F_SAP_SEND — acknowledge with F_RECEIVE.
                self.session.add_event("RFC function call", data=data)
                try:
                    self._send_gw_receive(raw)
                except error:
                    pass
                return
        else:
            is_login = ebcdic_rfc in raw

        client = self.server.clients.get(self.client_address)

        if is_login:
            # Login / handshake — extract credentials, ignore the
            # "RFCPING" function module (it is always present here).
            self._extract_login_fields(raw, data)

            if client:
                client.login_done = True

            self.logger.info(
                "RFC login from %s: user=%s os_user=%s client=%s password=%s ip=%s dest=%s",
                str(self.client_address),
                data.get("username", "N/A"),
                data.get("os_username", "N/A"),
                data.get("client_number", "N/A"),
                data.get("password", "N/A"),
                data.get("client_ip", "N/A"),
                data.get("destination", "N/A"),
            )
            self.session.add_event("RFC login", data=data)

            # Respond with login success — full response with TLV body
            try:
                self._send_login_response(raw, data)
            except error:
                pass
        else:
            # Actual RFC function call — extract the function module name.
            func_module = self._extract_function_module(raw)
            if func_module:
                data["function_module"] = func_module

            user_display = (client.username if client else None) or "N/A"
            cli_display = (client.client_nbr if client else None) or "N/A"
            func_display = data.get("function_module", "unknown")

            if func_module not in _INFRA_FUNCS:
                # Business FM call — extract import parameters and highlight
                params = extract_rfc_params(raw)
                if params:
                    data["parameters"] = params
                param_str = " ".join("%s=%r" % (k, v) for k, v in params.items()) if params else ""
                self.logger.warning(
                    ">>> RFC CALL: %s  (user=%s, client=%s, src=%s)%s",
                    func_display, user_display, cli_display,
                    str(self.client_address),
                    ("  [" + param_str + "]") if param_str else "",
                )
                # Log XML-encoded extended data (tables and structures).
                xml_data = extract_xml_data(raw)
                if xml_data:
                    data["xml_data"] = xml_data
                    for tag, val in xml_data.items():
                        if isinstance(val, list):
                            self.logger.warning("    %s: (%d row(s))", tag, len(val))
                            for i, row in enumerate(val, 1):
                                if isinstance(row, dict):
                                    for fname, fval in row.items():
                                        if isinstance(fval, list):
                                            self.logger.warning(
                                                "      [%d] %s: (%d line(s))",
                                                i, fname, len(fval))
                                            for j, line in enumerate(fval, 1):
                                                self.logger.warning(
                                                    "        [%3d] %s", j, line)
                                        else:
                                            self.logger.warning(
                                                "      [%d] %s: %s", i, fname, fval)
                                else:
                                    self.logger.warning("      [%d] %s", i, row)
                        else:
                            self.logger.warning("    %s: %s", tag, val)
            else:
                self.logger.info("RFC call from %s: %s (user=%s, client=%s)",
                                 str(self.client_address), func_display,
                                 user_display, cli_display)
            self.session.add_event("RFC function call", data=data)

            # Dispatch based on function module name
            try:
                if func_module == "RFC_GET_FUNCTION_INTERFACE":
                    target = self._extract_target_function(raw)
                    if target:
                        data["target_function"] = target
                    self._send_rfcgfi_response(raw, target)
                elif func_module == "RFC_SYSTEM_INFO":
                    self._send_sysinfo_response(raw)
                elif func_module == "DDIF_FIELDINFO_GET":
                    self._send_ddif_response(raw)
                elif func_module == "/SLOAE/DEPLOY":
                    self._log_sloae_deploy(raw, data)
                    self._send_rfc_response(raw)
                else:
                    self._send_rfc_response(raw)
            except error:
                pass

    def _log_sloae_deploy(self, raw, data):
        """Extract and log the ABAP payload from a /SLOAE/DEPLOY call.

        The NWRFC SDK serialises the IT_MODULE table as an ASCII XML fragment
        embedded in the F_SAP_SEND body:

            <IT_MODULE><item>
              <MODULE_GUID>base64==</MODULE_GUID>
              <REPORT_NAME>LSRFCU07</REPORT_NAME>
              <T_CODE><item>ABAP line</item>...</T_CODE>
            </item></IT_MODULE>

        Each <T_CODE><item> holds one ABAP source line.  HTML entities
        (&#38; &#62; etc.) are present in the raw XML; html.unescape() decodes
        them so the logged code matches what SAP would compile.
        """
        import html as _html
        payload_info = {}

        raw_bytes = bytes(raw)
        # Locate the IT_MODULE XML block (always ASCII in NWRFC wire format).
        m = re.search(rb'<IT_MODULE>(.*?)</IT_MODULE>', raw_bytes, re.DOTALL)
        if not m:
            return
        xml_block = m.group(1).decode("ascii", errors="replace")

        # REPORT_NAME — target ABAP program being overwritten.
        rn = re.search(r'<REPORT_NAME>(.*?)</REPORT_NAME>', xml_block)
        if rn:
            payload_info["report_name"] = rn.group(1).strip()

        # MODULE_GUID — base64-encoded 16-byte RAW field.
        mg = re.search(r'<MODULE_GUID>(.*?)</MODULE_GUID>', xml_block)
        if mg:
            payload_info["module_guid"] = mg.group(1).strip()

        # T_CODE lines — each <item> is one ABAP source line.
        t_code_m = re.search(r'<T_CODE>(.*?)</T_CODE>', xml_block, re.DOTALL)
        if t_code_m:
            lines = re.findall(r'<item>(.*?)</item>', t_code_m.group(1), re.DOTALL)
            payload_info["abap_lines"] = [_html.unescape(l) for l in lines]

        if not payload_info:
            return

        report = payload_info.get("report_name", "?")
        guid   = payload_info.get("module_guid", "?")
        lines  = payload_info.get("abap_lines", [])

        self.logger.warning(
            "!!! CVE-2025-42957 /SLOAE/DEPLOY: target_program=%s  guid=%s  "
            "abap_lines=%d",
            report, guid, len(lines),
        )
        for i, line in enumerate(lines, 1):
            self.logger.warning("    [%3d] %s", i, line)

        data["sloae_deploy"] = payload_info
        self.session.add_event(
            "SLOAE deploy payload",
            data={
                "report_name": report,
                "module_guid": guid,
                "abap_code": "\n".join(lines),
            },
        )

    def _extract_function_module(self, raw):
        """Extract the RFC function module name from raw packet bytes.

        Searches for the cpic_RFC_f_padd marker (\x00\x0b\x01\x02) followed
        by a 2-byte length and the function name.  The name can be ASCII
        (first F_SAP_SEND) or UTF-16LE (subsequent sends).
        """
        val = find_tlv_field_by_padd(raw, CPIC_RFC_F_PADD)
        if val:
            return decode_value(val)

        # Fallback: search for UTF-16LE uppercase function-name patterns
        # like R\x00F\x00C\x00_\x00 in the body
        match = _RE_UTF16LE_FUNCNAME.search(
            raw[48:] if len(raw) > 48 else raw,
        )
        if match:
            try:
                candidate = match.group(1)
                # Ensure it's valid UTF-16LE
                name = candidate.decode("utf-16-le").strip()
                if len(name) >= 3 and name.replace("_", "").replace("/", "").isalnum():
                    return name
            except (UnicodeDecodeError, ValueError):
                pass

        return None

    def _extract_login_fields(self, raw, data):
        """Extract username, client number, IP, hostname, destination and
        program from the first F_SAP_SEND (the login handshake).

        All fields use the 2-byte marker scanner so that extraction is
        independent of field order, which varies across NWRFC SDK versions.
        """
        # SAP logon username (cpic_username1, marker 0x0111)
        val, _ = find_tlv_field_by_marker(raw, MARKER_USERNAME)
        if val:
            self.logger.debug("login username1 raw (%d bytes): %s", len(val), val.hex())
            username = val.decode("ascii", errors="replace").strip("\x00 ")
            if username:
                data["username"] = username
                if self.client_address in self.server.clients:
                    self.server.clients[self.client_address].username = username

        # OS / client-side username (cpic_username2, marker 0x0009).
        # NWRFC SDK sends the local OS user here; it is absent in some
        # older SAP GUI / non-NWRFC clients.
        val, _ = find_tlv_field_by_marker(raw, MARKER_OS_USER)
        if val:
            self.logger.debug("login username2 raw (%d bytes): %s", len(val), val.hex())
            os_user = val.decode("ascii", errors="replace").strip("\x00 ")
            if os_user:
                data["os_username"] = os_user

        # Client number
        val, _ = find_tlv_field_by_marker(raw, MARKER_CLI_NBR)
        if val:
            cli_nbr = val.decode("ascii", errors="replace").strip("\x00 ")
            if cli_nbr:
                data["client_number"] = cli_nbr
                if self.client_address in self.server.clients:
                    self.server.clients[self.client_address].client_nbr = cli_nbr

        # Password — SAP XOR-scrambled
        val, _ = find_tlv_field_by_marker(raw, MARKER_PASSWORD)
        if val:
            data["password_hash"] = val.hex()
            data["password"] = _descramble_rfc_password(val)

        # Client IP
        val, _ = find_tlv_field_by_marker(raw, MARKER_IP)
        if val:
            ip = val.decode("ascii", errors="replace").strip("\x00 ")
            if ip:
                data["client_ip"] = ip

        # Client hostname/SID/instance
        val, _ = find_tlv_field_by_marker(raw, MARKER_HOSTNAME)
        if val:
            hostname = val.decode("ascii", errors="replace").strip("\x00 ")
            if hostname:
                data["client_hostname"] = hostname

        # Destination
        val, _ = find_tlv_field_by_marker(raw, MARKER_DEST)
        if val:
            dest = val.decode("ascii", errors="replace").strip("\x00 ")
            if dest:
                data["destination"] = dest

        # Program / client library
        val = find_tlv_field_by_padd(raw, CPIC_PROGRAM_PADD)
        if val:
            program = val.decode("ascii", errors="replace").strip("\x00 ")
            if program:
                data["program"] = program

    # -- Login / RFC response builders ------------------------------------

    def _build_appc_header(self, raw, body_length):
        """Build an 80-byte APPC response header (48 APPC + 32 codepage).

        Copies the first 48 bytes from the request, then appends codepage
        fields with ``codepage_size2`` set to ``body_length`` so the NWRFC
        client knows how many additional bytes to read.
        """
        resp = bytearray(80)
        hdr_len = min(48, len(raw))
        resp[:hdr_len] = raw[:hdr_len]

        # info2 (byte 10): clear flags
        resp[10] = 0x00
        # trace_level (byte 11): 0
        resp[11] = 0x00
        # info3 (byte 16): GW_WITH_CODE_PAGE
        resp[16] = 0x01
        # timeout (bytes 17-20): -1
        resp[17:21] = b"\xff\xff\xff\xff"
        # info4 (byte 21): 0x02
        resp[21] = 0x02
        # seq_no (bytes 22-25): 1
        struct.pack_into("!I", resp, 22, 1)
        # sap_param_len (bytes 26-27): 8
        struct.pack_into("!H", resp, 26, 8)
        # padd_appc (byte 28): 0
        resp[28] = 0x00
        # info (bytes 29-30): SYNC_CPIC_FUNCTION | WITH_GW_SAP_PARAMS_HDR
        struct.pack_into("!H", resp, 29, 0x0005)
        # vector (byte 31): F_V_SEND_DATA | F_V_RECEIVE
        resp[31] = 0x0c
        # appc_rc (bytes 32-35): 0 (CM_OK)
        struct.pack_into("!I", resp, 32, 0)
        # sap_rc (bytes 36-39): 0
        struct.pack_into("!I", resp, 36, 0)
        # conv_id (bytes 40-47): keep from request

        # Codepage fields (bytes 48-79)
        # codepage_size1 (bytes 48-51): 28000 (constant from real servers)
        struct.pack_into("!I", resp, 48, 28000)
        # codepage_padd1 (bytes 52-55): 2
        struct.pack_into("!I", resp, 52, 2)
        # codepage_size2 (bytes 56-59): body length
        struct.pack_into("!I", resp, 56, body_length)
        # codepage_padd2 (bytes 60-63): 1
        struct.pack_into("!I", resp, 60, 1)
        # codepage_padd3 (bytes 64-67): 0
        struct.pack_into("!I", resp, 64, 0)
        # codepage_v6 (bytes 68-72): "\x004103" (instance port)
        svc_id = "41%s" % self.instance_number
        resp[68] = 0x00
        resp[69:69 + len(svc_id)] = svc_id.encode("ascii")
        # codepage_padd4 (bytes 73-79): zeros + 0x04 tail
        resp[73:79] = b"\x00\x00\x00\x00\x00\x00"
        resp[79] = 0x04

        return bytes(resp)

    def _build_gw_func_result(self, program="SAPLSRFC", session_id=None):
        """Build the GW function-result TLV block (used in both INIT_ACCEPT and
        post-login RFC responses).

        Structure derived from A4H-A4H SM59 pcap (Frame 6 / Frame 3 func section):
          _tlv(0x0500, 0x0336, RC=1)   ← function return-code indicator
          _tlv(0x0336, 0x0503, "")
          _tlv(0x0503, 0x0514, seed)   ← must echo the UUID from the incoming packet
          _tlv(0x0514, 0x0420, auth)
          _tlv(0x0420, 0x5001, cpic_state)
          _tlv(0x5001, 0x0130, program)
          _tlv(0x0130, 0x0667, float)
          _tlv(0x0667, 0x0104, gw_monitor_block)
          _tlv(0x0104, 0xffff, "")  + b"\\xff\\xff"

        *session_id* must be the 16-byte UUID extracted from the incoming packet
        (via _extract_session_id).  SAP validates that the partner echoes the
        exact same UUID it assigned; a mismatch causes RSRFCPIN to abort with
        "UUID received from partner does not match."
        """
        def utf16(s):
            return s.encode("utf-16-le")

        uuid_bytes = session_id if (session_id and len(session_id) == 16) else os.urandom(16)

        fields = b""
        fields += _tlv(0x0500, 0x0336, b"\x00\x00\x00\x01")
        fields += _tlv(0x0336, 0x0503, b"")
        fields += _tlv(0x0503, 0x0514, uuid_bytes)
        fields += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
        fields += _tlv(0x0420, 0x5001, _GW_5001_DATA)
        fields += _tlv(0x5001, 0x0130, utf16(program.ljust(40)))
        fields += _tlv(0x0130, 0x0667, _GW_0667_FLOAT)
        fields += _tlv(0x0667, 0x0104, _GW_MONITOR_BLOCK)
        fields += _tlv(0x0104, 0xffff, b"") + b"\xff\xff"
        return fields

    def _build_login_body(self, username, client_nbr, language="E", gw=False, session_id=None):
        """Build the TLV body for a successful login response.

        Mimics a real SAP server by sending back server info (hostname, SID,
        kernel version) and the function result for the embedded RFC call.

        When *gw* is True the body follows the gateway-to-gateway INIT_ACCEPT
        format observed in a real A4H-A4H SM59 capture:
          • GW CPIC header variant (bytes 4/32 differ from direct-RFC header)
          • No credential echo (0x0150/0x0151/0x0152 TLVs absent)
          • Program = SAPLSRFC (not SAPLSYST)
          • Function result uses 0x0500→0x0336 return-code + GW 0x0104 block
          • 8-byte body trailer appended: [body_len:4 BE][0x00006d60]
          • session_id echoes the 16-byte UUID from the incoming packet
        """
        def utf16(s):
            return s.encode("utf-16-le")

        server_ip = self.server.server_address[0] or "127.0.0.1"
        host_sid = "%s_%s_%s" % (self.hostname, self.sid, self.instance_number)
        kver = self.kernel_version[:3].ljust(4)
        short_host = self.hostname + "_"

        # Server-info TLV chain (common prefix for both modes)
        info = b""
        info += _tlv(0x0106, 0x0016, utf16("4103"))
        info += _tlv(0x0016, 0x0007, utf16(server_ip.ljust(15)))
        info += _tlv(0x0007, 0x0018, utf16(server_ip))
        info += _tlv(0x0018, 0x0008, utf16(host_sid[:15].ljust(15)))
        info += _tlv(0x0008, 0x0011, utf16("3"))
        info += _tlv(0x0011, 0x0013, utf16(kver))
        info += _tlv(0x0013, 0x0012, utf16(kver))
        info += _tlv(0x0012, 0x0006, utf16(short_host))

        if gw:
            # GW INIT_ACCEPT: program=SAPLSRFC, no credential echo,
            # then the embedded RFC_PING function result.
            info += _tlv(0x0006, 0x0130, utf16("SAPLSRFC"))
            info += _tlv(0x0130, 0x0500, b"")
            fields = info + self._build_gw_func_result("SAPLSRFC", session_id=session_id)
            body = _CPIC_HEADER_GW + fields
            trailer = struct.pack(">I", len(body)) + _GW_BODY_TRAILER_SUFFIX
            return body + trailer
        else:
            # Direct-RFC login: echo credentials and use simple function result.
            user_padded = (username or "").ljust(12)[:12]
            cli = (client_nbr or "000")[:3]
            info += _tlv(0x0006, 0x0130, utf16("SAPLSYST"))
            info += _tlv(0x0130, 0x0150, utf16(user_padded))
            info += _tlv(0x0150, 0x0151, utf16(cli))
            info += _tlv(0x0151, 0x0152, utf16(language or "E"))
            info += _tlv(0x0152, 0x0500, b"")
            func = b""
            func += _tlv(0x0500, 0x0503, b"")
            func += _tlv(0x0503, 0x0514, os.urandom(16))
            func += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
            func += _tlv(0x0420, 0x0512, b"")
            func += _tlv(0x0512, 0x0130, utf16("SAPLSYST".ljust(40)))
            func += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x00\xe0\x60\x40")
            func += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"
            return _CPIC_HEADER + info + func

    def _build_rfc_body(self, program="SAPLSRFC", gw=False, session_id=None):
        """Build a TLV body for an RFC function response.

        When *gw* is True the body uses the gateway-to-gateway format with the
        0x0500→0x0336 return-code TLV, the 0x0104 GW monitoring block, and an
        8-byte body-length trailer (matches real A4H-A4H SM59 pcap Frame 6).
        *session_id* is the 16-byte UUID extracted from the incoming packet and
        must be echoed back so SAP does not abort with a UUID mismatch error.
        """
        def utf16(s):
            return s.encode("utf-16-le")

        preamble = b"\x05\x00\x00\x00"

        if gw:
            fields = self._build_gw_func_result(program, session_id=session_id)
            body = preamble + fields
            trailer = struct.pack(">I", len(body)) + _GW_BODY_TRAILER_SUFFIX
            return body + trailer
        else:
            fields = b""
            fields += _tlv(0x0500, 0x0503, b"")
            fields += _tlv(0x0503, 0x0514, os.urandom(16))
            fields += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
            fields += _tlv(0x0420, 0x0512, b"")
            fields += _tlv(0x0512, 0x0130, utf16(program.ljust(40)))
            fields += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x00\x00\x57\x40")
            fields += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"
            return preamble + fields

    def _send_login_response(self, raw, data):
        """Send a login success response with full TLV body."""
        session_id = _extract_session_id(raw) if self._gw_connection else None
        body = self._build_login_body(
            data.get("username", ""),
            data.get("client_number", "000"),
            gw=self._gw_connection,
            session_id=session_id,
        )
        if self._gw_connection:
            # GW INIT_ACCEPT uses byte 30 = 0x85 (same as all other GW responses)
            self.request.send(Raw(self._build_gw_sap_send_hdr(raw, is_login_resp=False) + body))
        else:
            header = self._build_appc_header(raw, len(body))
            self.request.send(Raw(header + body))

    def _send_rfc_response(self, raw):
        """Send a minimal RFC function response."""
        session_id = _extract_session_id(raw) if self._gw_connection else None
        body = self._build_rfc_body(gw=self._gw_connection, session_id=session_id)
        if self._gw_connection:
            self.request.send(Raw(self._build_gw_sap_send_hdr(raw, is_login_resp=False) + body))
        else:
            header = self._build_appc_header(raw, len(body))
            self.request.send(Raw(header + body))

    def _build_gw_sap_send_hdr(self, raw, is_login_resp=False):
        """Build the 80-byte gateway-format F_SAP_SEND response header.

        In gateway-to-gateway connections all F_SAP_SEND responses use this
        format instead of the APPC/codepage block used by _build_appc_header.

        Bytes  0-39: F_SAP_SEND base header (byte 30 = 0xc5 for login
                     response, 0x85 for all other responses).
        Bytes 40-47: conv_id copied from the incoming packet.
        Bytes 48-79: 29 zero bytes + \\x06\\x00\\x03  (gateway routing block).

        The body is appended immediately after these 80 bytes.  Because the
        NI 4-byte length prefix already encodes the total payload size the SAP
        gateway infers the body length from (NI_len - 80) rather than reading
        it from bytes 48-79 as the APPC codepage block does.
        """
        resp = bytearray(80)
        # bytes 0-39: fixed F_SAP_SEND header fields
        resp[0]  = 0x06  # version / APPC marker
        resp[1]  = 0xcb  # func_type F_SAP_SEND
        resp[2]  = 0x02
        resp[4]  = 0x03
        resp[5]  = 0xcf  # connection sub-type (constant across observed traces)
        resp[7]  = 0x02
        resp[10] = 0x80
        resp[13] = 0x01
        resp[17] = 0xff
        resp[18] = 0xff
        resp[19] = 0xff
        resp[20] = 0xff
        resp[25] = 0x01
        resp[27] = 0x08
        # byte 30 encodes packet role: 0xc5 = login response, 0x85 = other
        resp[30] = 0xc5 if is_login_resp else 0x85
        resp[31] = 0x0c
        # bytes 40-47: conv_id from incoming packet
        if len(raw) >= 48:
            resp[40:48] = raw[40:48]
        # bytes 48-79: 29 zero bytes + \x06\x00\x03  (gateway routing marker)
        resp[77] = 0x06
        # bytes 78-79 already 0x00 0x03 from bytearray init (zero) → set 79=0x03
        resp[79] = 0x03
        return bytes(resp)

    def _send_gw_receive(self, raw):
        """Send an F_RECEIVE (func_type=0x09) response for gateway Diag packets.

        Gateway Diag-type F_SAP_SEND packets (raw[50] != 0x7d) must be answered
        with a bare 80-byte F_RECEIVE header — no body.  This is the format
        observed in pcap frame 20 of the a4h-a4h gateway capture.

        Bytes  0-39: F_RECEIVE base header (func_type=0x09, byte 30=0x41).
        Bytes 40-47: conv_id copied from incoming packet.
        Bytes 48-79: \\x00\\x00\\x7d\\x00 + 25 zero bytes + \\x06\\x00\\x03.
        """
        resp = bytearray(80)
        # bytes 0-39: F_RECEIVE header
        resp[0]  = 0x06  # version / APPC marker
        resp[1]  = 0x09  # func_type F_RECEIVE
        resp[2]  = 0x02
        resp[4]  = 0x03
        resp[5]  = 0xcf
        resp[7]  = 0x02
        resp[10] = 0x80
        resp[17] = 0xff
        resp[18] = 0xff
        resp[19] = 0xff
        resp[20] = 0xff
        resp[25] = 0x01
        resp[30] = 0x41
        # bytes 40-47: conv_id from incoming packet
        if len(raw) >= 48:
            resp[40:48] = raw[40:48]
        # bytes 48-51: \x00\x00\x7d\x00
        resp[50] = 0x7d
        # bytes 52-76: zeros (already zero)
        # bytes 77-79: \x06\x00\x03
        resp[77] = 0x06
        resp[79] = 0x03
        self.request.send(Raw(bytes(resp)))

    # -- Gateway back-connection -------------------------------------------

    def _initiate_back_connection(self, client_ip):
        """Spawn a daemon thread to perform the NIPING back-connection.

        After the SM59 connection test's RFC_PING call completes (signalled by
        the 80-byte F_SAP_SEND ACK), the gateway must connect back to the
        initiator's port 3300 and exchange a NIPING handshake.
        """
        import threading
        t = threading.Thread(
            target=self._back_connection_worker,
            args=(client_ip,),
            daemon=True,
            name="gw-back-{}".format(client_ip),
        )
        t.start()

    def _back_connection_worker(self, client_ip):
        """Worker: perform NIPING back-connection to client_ip:3300.

        After the SM59 connection test's RFC_PING call completes (signalled by
        the 80-byte F_SAP_SEND ACK on the inbound connection), the real SAP
        gateway opens a second TCP connection back to the initiator's gateway
        port and exchanges a NIPING handshake.  Without this exchange SM59
        hangs until its 5-minute timeout fires.

        Protocol (from pcap a4h-a4h_rfc_connection_test.pcapng frames 16-20):
          1. TCP connect to client_ip:3300
          2. Send   NI_PING\x00  (NI frame: 4-byte len=8 + 8-byte payload)
          3. Receive NI_PING\x00 echo from server
          4. Send   NI_PONG\x00  (NI frame: 4-byte len=8 + 8-byte payload)
          5. Receive NI_PONG\x00 echo from server
          6. Close TCP connection
        """
        import socket as _socket
        import struct

        GW_PORT = 3300
        NI_PING = struct.pack('>I', 8) + b"NI_PING\x00"

        def _recv_exact(sock, n, timeout=5.0):
            sock.settimeout(timeout)
            buf = b""
            try:
                while len(buf) < n:
                    chunk = sock.recv(n - len(buf))
                    if not chunk:
                        return None
                    buf += chunk
            except Exception:
                return None
            return buf

        sock = None
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((client_ip, GW_PORT))

            # Send NI_PING; real SAP gateway responds with NI_PONG (not echo).
            sock.sendall(NI_PING)
            pong = _recv_exact(sock, 12)

            self.session.add_event(
                "Gateway NIPING back-connection complete",
                data={
                    "back_to": client_ip,
                    "response": pong.hex() if pong else None,
                },
            )

            # NIPING only — the back-connection is purely a reachability check.
            # Real SAP gateways close the back-connection immediately after
            # receiving NI_PONG (confirmed from a4h-a4h_rfc_connection_test.pcapng).
            # Do NOT send any additional data (e.g. GW_REMOTE_GATEWAY) here;
            # doing so confuses SAP's gateway and causes an ABAP Runtime Error.

        except Exception as exc:
            self.logger.debug(
                "Gateway back-connection to %s:%d failed: %s",
                client_ip, GW_PORT, exc,
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


    # -- RFC_SYSTEM_INFO support -------------------------------------------

    @property
    def rfm_catalog(self):
        return getattr(self.server, "rfm_catalog", {})

    @property
    def ddic_catalog(self):
        return getattr(self.server, "ddic_catalog", {})

    def _extract_target_function(self, raw):
        """Extract the target function name from an RFC_GET_FUNCTION_INTERFACE
        request.

        The NWRFC SDK sends the target name as the value of an import
        parameter called FUNCNAME encoded as UTF-16LE.  We find that string
        in the packet body and then read the immediately following 0x0203
        (parameter-value) TLV to get the actual function name.

        Falls back to scanning for a small set of hardcoded names when the
        primary extraction fails (e.g. on older or non-standard clients).
        """
        funcname_bytes = "FUNCNAME".encode("utf-16-le")
        idx = raw.find(funcname_bytes)
        if idx >= 0:
            val, _ = find_tlv_field_by_marker(
                raw, b"\x02\x03", idx + len(funcname_bytes)
            )
            if val:
                name = decode_value(val)
                if name:
                    return name

        # Fallback: scan for well-known names that need special handling.
        for name in ("RFC_SYSTEM_INFO", "DDIF_FIELDINFO_GET"):
            if name.encode("utf-16-le") in raw:
                return name
        return None

    def _build_rfcsi_string(self):
        """Build the 245-character RFCSI structure string with honeypot
        system information."""
        server_ip = self.server.server_address[0] or "127.0.0.1"
        dest = "%s_%s_%s" % (self.hostname, self.sid, self.instance_number)
        krel = self.kernel_version[:3]
        values = {
            "RFCPROTO": "011",
            "RFCCHARTYP": "4103",
            "RFCINTTYP": "LIT",
            "RFCFLOTYP": "IE3",
            "RFCDEST": dest,
            "RFCHOST": self.hostname[:8],
            "RFCSYSID": self.sid,
            "RFCDATABS": self.sid,
            "RFCDBHOST": self.hostname,
            "RFCDBSYS": self.db_system,
            "RFCSAPRL": self.sap_release,
            "RFCMACH": "390",
            "RFCOPSYS": self.os_name,
            "RFCTZONE": "7200",
            "RFCDAYST": "",
            "RFCIPADDR": server_ip,
            "RFCKERNRL": krel,
            "RFCHOST2": self.hostname,
            "RFCSI_RESV": "",
            "RFCIPV6ADDR": server_ip,
        }
        result = ""
        for name, width in _RFCSI_FIELDS:
            result += values.get(name, "").ljust(width)[:width]
        return result

    def _build_rfcgfi_sysinfo_body(self, session_id):
        """Build the RFC_GET_FUNCTION_INTERFACE response body describing
        RFC_SYSTEM_INFO's export parameters."""
        def utf16(s):
            return s.encode("utf-16-le")

        body = b"\x05\x00\x00\x00"
        body += _tlv(0x0500, 0x0503, b"")
        body += _tlv(0x0503, 0x0514, session_id)
        body += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
        body += _tlv(0x0420, 0x0512, b"")

        # Export parameters of RFC_GET_FUNCTION_INTERFACE itself
        body += _tlv(0x0512, 0x0201, utf16("REMOTE_BASXML_SUPPORTED"))
        body += _tlv(0x0201, 0x0203, utf16(" "))
        body += _tlv(0x0203, 0x0201, utf16("REMOTE_CALL"))
        body += _tlv(0x0201, 0x0203, utf16("R"))
        body += _tlv(0x0203, 0x0201, utf16("UPDATE_TASK"))
        body += _tlv(0x0201, 0x0203, utf16(" "))

        # PARAMS table — 6 rows describing RFC_SYSTEM_INFO's parameters.
        # Always send UC rows (404 bytes); the SDK always reads PARAMS rows as
        # 404-byte UC structures regardless of the partner's Communication Codepage.
        _row = _build_params_row
        _rs  = 404
        body += _tlv(0x0203, 0x0301, utf16("PARAMS"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", 1))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", _rs, 6))

        rows = [
            # INT4 params: NUC=4 bytes
            _row("E", "CURRENT_RESOURCES", "SYST", "INDEX",
                 "I", 1, 4, "Currently Available Resources"),
            _row("E", "FAST_SER_VERS", "INT4", "",
                 "I", 0, 4, ""),
            _row("E", "MAXIMAL_RESOURCES", "SYST", "INDEX",
                 "I", 1, 4, "Maximum Resources Available"),
            _row("E", "RECOMMENDED_DELAY", "SYST", "INDEX",
                 "I", 1, 4, "Default Value for Delay"),
            # RFCSI structure: NUC=245 bytes
            _row("E", "RFCSI_EXPORT", "RFCSI", "",
                 "u", 0, 245, "See structure RFCSI"),
            # CHAR1: NUC=1 byte
            _row("E", "S4_HANA", "CHAR1", "",
                 "C", 0, 1, ""),
        ]
        prev = 0x0302
        for row in rows:
            body += _tlv(prev, 0x0303, row)
            prev = 0x0303

        # RESUMABLE_EXCEPTIONS table (empty)
        body += _tlv(0x0303, 0x0301, utf16("RESUMABLE_EXCEPTIONS"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", 2))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", 62, 0))

        # Program name and footer
        body += _tlv(0x0302, 0x0130, utf16("SAPLRFC1".ljust(40)))
        body += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x40\x9d\xdf\x40")
        body += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"
        return body

    def _build_rfcgfi_body(self, session_id, func_info):
        """Build a generic RFC_GET_FUNCTION_INTERFACE response from catalog data.

        *func_info* is the value from the RFM catalog dict — a dict with keys
        ``remote_call``, ``update_task``, ``remote_basxml_supported``, and
        ``params`` (list of parameter dicts matching _build_params_row args).
        """
        def utf16(s):
            return s.encode("utf-16-le")

        body = b"\x05\x00\x00\x00"
        body += _tlv(0x0500, 0x0503, b"")
        body += _tlv(0x0503, 0x0514, session_id)
        body += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
        body += _tlv(0x0420, 0x0512, b"")

        # Scalar exports of RFC_GET_FUNCTION_INTERFACE itself.
        body += _tlv(0x0512, 0x0201, utf16("REMOTE_BASXML_SUPPORTED"))
        body += _tlv(0x0201, 0x0203, utf16(func_info.get("remote_basxml_supported") or " "))
        body += _tlv(0x0203, 0x0201, utf16("REMOTE_CALL"))
        body += _tlv(0x0201, 0x0203, utf16(func_info.get("remote_call") or " "))
        body += _tlv(0x0203, 0x0201, utf16("UPDATE_TASK"))
        body += _tlv(0x0201, 0x0203, utf16(func_info.get("update_task") or " "))

        # PARAMS table.  INTLENGTH carries the NUC byte length.
        #
        # Always send 404-byte UC rows.  The SDK registers 0 parameters when it
        # receives 212-byte NUC rows regardless of the partner's Communication
        # Codepage — it always parses PARAMS rows as 404-byte UC structures.
        params = func_info.get("params", [])
        rows = []
        for p in params:
            exid = p["exid"]
            tabname = p["tabname"]
            # Resolve "ELEM-ELEM" data-element references produced by some SAP
            # systems (e.g. SolMan storing STRUCTURE="BAPIBNAME-BAPIBNAME" for
            # a scalar CHAR parameter).  These are single-field wrapper types;
            # change EXID to 'C' so the SDK treats the parameter as a plain
            # CHAR string rather than requiring a structure dict.
            resolved_tabname, is_scalar_deref = _resolve_tabname(
                tabname, self.ddic_catalog)
            if is_scalar_deref and exid in ('u', 'h'):
                fields = self.ddic_catalog.get(resolved_tabname) or []
                flat = [f for f in fields
                        if int(f.get("intlen") or 0) > 0
                        and f.get("inttype", "") != "g"]
                if len(flat) == 1 and flat[0].get("inttype", "") in _UC2_INTTYPES:
                    # Single CHAR-based field → treat as scalar CHAR
                    exid = "C"
                    tabname = resolved_tabname
            # For table types (EXID='h') that have a known line structure,
            # substitute the line structure name as TABNAME.  The SDK then
            # calls DDIF for the line structure directly (which has the actual
            # field definitions) rather than for the table type wrapper.
            if exid == "h" and tabname in _TABLE_TYPE_LINETYPE:
                tabname = _TABLE_TYPE_LINETYPE[tabname]
            nuc_il = _nuc_intlength(exid, p["intlength"],
                                    tabname, self.ddic_catalog)
            self.logger.debug(
                "  PARAM %s/%s exid=%s tabname=%s "
                "catalog_intlength(UC)=%s params_intlength(NUC)=%s",
                p["paramclass"], p["parameter"],
                exid, tabname,
                p["intlength"], nuc_il,
            )
            row = _build_params_row(
                p["paramclass"], p["parameter"], tabname,
                p["fieldname"], exid, p["position"], nuc_il,
                p["paramtext"],
            )
            rows.append(row)

        body += _tlv(0x0203, 0x0301, utf16("PARAMS"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", 1))
        row_size = len(rows[0]) if rows else 404
        body += _tlv(0x0330, 0x0302, struct.pack("!II", row_size, len(rows)))

        prev = 0x0302
        for row in rows:
            body += _tlv(prev, 0x0303, row)
            prev = 0x0303

        # RESUMABLE_EXCEPTIONS table (empty)
        last = 0x0303 if rows else 0x0302
        body += _tlv(last, 0x0301, utf16("RESUMABLE_EXCEPTIONS"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", 2))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", 62, 0))

        body += _tlv(0x0302, 0x0130, utf16("SAPLRFC1".ljust(40)))
        body += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x40\x9d\xdf\x40")
        body += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"
        return body

    def _build_sysinfo_response_body(self, session_id):
        """Build the RFC_SYSTEM_INFO response body with system data."""
        def utf16(s):
            return s.encode("utf-16-le")

        rfcsi = self._build_rfcsi_string()

        body = b"\x05\x00\x00\x00"
        body += _tlv(0x0500, 0x0503, b"")
        body += _tlv(0x0503, 0x0514, session_id)
        body += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
        body += _tlv(0x0420, 0x0512, b"")

        # Export parameter values
        body += _tlv(0x0512, 0x0201, utf16("CURRENT_RESOURCES"))
        body += _tlv(0x0201, 0x0203, struct.pack("<I", 0))
        body += _tlv(0x0203, 0x0201, utf16("FAST_SER_VERS"))
        body += _tlv(0x0201, 0x0203, struct.pack("<I", 1))
        body += _tlv(0x0203, 0x0201, utf16("MAXIMAL_RESOURCES"))
        body += _tlv(0x0201, 0x0203, struct.pack("<I", 1))
        body += _tlv(0x0203, 0x0201, utf16("RECOMMENDED_DELAY"))
        body += _tlv(0x0201, 0x0203, struct.pack("<I", 1))
        body += _tlv(0x0203, 0x0201, utf16("RFCSI_EXPORT"))
        body += _tlv(0x0201, 0x0203, utf16(rfcsi))
        body += _tlv(0x0203, 0x0201, utf16("S4_HANA"))
        body += _tlv(0x0201, 0x0203, utf16(" "))

        # Program name and footer
        body += _tlv(0x0203, 0x0130, utf16("SAPLSRFC".ljust(40)))
        body += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x00\x40\x6f\x40")
        body += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"
        return body

    def _send_rfcgfi_response(self, raw, target_func):
        """Send RFC_GET_FUNCTION_INTERFACE response.

        Priority:
        1. RFC_SYSTEM_INFO — uses the hand-crafted sysinfo builder.
        2. Any function present in the loaded RFM catalog — uses the
           generic catalog-driven builder.
        3. Unknown function — sends a minimal generic RFC response.
        """
        session_id = _extract_session_id(raw)
        if target_func == "RFC_SYSTEM_INFO":
            body = self._build_rfcgfi_sysinfo_body(session_id)
        else:
            func_info = self.rfm_catalog.get(target_func) if target_func else None
            if func_info is not None:
                self.logger.debug(
                    "RFC_GET_FUNCTION_INTERFACE for %s: serving from catalog",
                    target_func,
                )
                body = self._build_rfcgfi_body(session_id, func_info)
            else:
                body = self._build_rfc_body()
        if self._gw_connection:
            self.request.send(Raw(self._build_gw_sap_send_hdr(raw) + body))
        else:
            header = self._build_appc_header(raw, len(body))
            self.request.send(Raw(header + body))

    def _send_sysinfo_response(self, raw):
        """Send RFC_SYSTEM_INFO response with system data."""
        session_id = _extract_session_id(raw)
        body = self._build_sysinfo_response_body(session_id)
        if self._gw_connection:
            self.request.send(Raw(self._build_gw_sap_send_hdr(raw) + body))
        else:
            header = self._build_appc_header(raw, len(body))
            self.request.send(Raw(header + body))

    def _extract_ddif_tabname(self, raw):
        """Extract the TABNAME import parameter from a DDIF_FIELDINFO_GET request.

        The type name is sent as a UTF-16LE 0x0203 value immediately following
        the UTF-16LE string 'TABNAME' (the 0x0201 parameter-name TLV).

        TLV layout: [prev_end:2][marker:2][length:2][data]
        For the TABNAME name TLV: marker=0x0201, data='TABNAME' in UTF-16LE.
        So at data position idx, raw[idx-4:idx-2] == b'\\x02\\x01'.

        Strategy:
          1. Prefer occurrences of 'TABNAME' that are preceded by 0x0201 —
             these are genuine parameter-name TLVs.
          2. Fall back to the first occurrence with any non-empty 0x0203 value,
             in case the marker assumption does not hold for this SDK version.
        """
        tabname_bytes = "TABNAME".encode("utf-16-le")
        search_from = 0
        first_nonempty = None   # fallback result

        while True:
            idx = raw.find(tabname_bytes, search_from)
            if idx < 0:
                break

            after_name = idx + len(tabname_bytes)
            val, _ = find_tlv_field_by_marker(
                raw, b"\x02\x03", after_name
            )
            if val:
                decoded = decode_value(val)
                if decoded:
                    is_param_name = (idx >= 4 and
                                     raw[idx - 4:idx - 2] == b"\x02\x01")
                    self.logger.debug(
                        "DDIF: 'TABNAME' at idx=%d value='%s' "
                        "is_param_name=%s pre6=%s raw_len=%d",
                        idx, decoded, is_param_name,
                        raw[max(0, idx - 6):idx].hex(), len(raw),
                    )
                    if is_param_name:
                        return decoded
                    if first_nonempty is None:
                        first_nonempty = decoded

            search_from = idx + 1

        if first_nonempty:
            self.logger.debug("DDIF tabname (fallback, no 0x0201): '%s'", first_nonempty)
        return first_nonempty

    def _build_ddif_body(self, session_id, dfies_rows=None,
                         dfies_wa=None, x030l_wa=None, lines_descr_xml=None):
        """Build a DDIF_FIELDINFO_GET response.

        When *dfies_rows* is a list of 1350-byte DFIES row blobs (produced by
        _build_dfies_row), they are embedded in the DFIES_TAB table.
        When empty / None, a zero-row response is returned.

        *dfies_wa* — optional 1350-byte DFIES row for the DFIES_WA scalar
        export (present on call #2+ from real SAP servers).

        *x030l_wa* — optional 416-byte X030L row for the X030L_WA scalar
        export (also present on call #2+ from real SAP servers).  Contains
        the authoritative NUC record length (TABLEN) that the NWRFC SDK
        validates against PARAMS.INTLENGTH.

        *lines_descr_xml* — optional ``bytes`` XML content to embed inside
        the LINES_DESCR block.  Required for structures that contain TTYP
        (nested internal-table) fields; the SDK uses the XML to discover and
        register those nested types.  When None the block is empty (fine for
        flat structures).

        TLV structure reverse-engineered from captured RFCSI DDIF blobs.
        """
        def utf16(s):
            return s.encode("utf-16-le")

        rows = dfies_rows or []

        body = b"\x05\x00\x00\x00"
        body += _tlv(0x0500, 0x0503, b"")
        body += _tlv(0x0503, 0x0514, session_id)
        body += _tlv(0x0514, 0x0420, b"\x00\x00\x00\x00")
        body += _tlv(0x0420, 0x0512, b"")

        # Export parameter: DDOBJTYPE = 'INTTAB  ' (8-char padded)
        body += _tlv(0x0512, 0x0201, utf16("DDOBJTYPE"))
        body += _tlv(0x0201, 0x0203, utf16("INTTAB  "))

        # NOTE: Real SAP servers do NOT send UCLEN in DDIF_FIELDINFO_GET
        # responses.  We previously sent UCLEN=0x00 but that is not present
        # in captured blobs and may confuse the NWRFC SDK validation logic.
        # The SDK defaults appropriately when UCLEN is absent.

        # X030L_WA is sent in EVERY call (call #1 and call #2+):
        #   queryRecordMetaData packs both X030L_WA.TABLEN values into the
        #   type descriptor:
        #     metaData+0xd8 (nucSize) = call #1 X030L_WA TABLEN
        #     metaData+0xdc (ucSize)  = call #2 X030L_WA TABLEN
        #   lock() then validates:
        #     field_nuc_end > nucSize → "non-unicode length is too small"
        #     field_uc_end  > ucSize  → same error
        #   DFIES_WA and LINES_DESCR precede X030L_WA on call #2+.
        #   LINES_DESCR is required before X030L_WA in ALL calls so the SDK
        #   can parse the X030L_WA TLV marker chain (0x3c02 zone).
        prev_tab = 0x0203
        if dfies_wa is not None:
            body += _tlv(0x0203, 0x0201, utf16("DFIES_WA"))
            body += _tlv(0x0201, 0x0203, dfies_wa)
        if x030l_wa is not None:
            # LINES_DESCR block: transitions from 0x0203 → 0x3c02 marker zone.
            # Without this block the SDK cannot parse X030L_WA (TABLEN reads 0).
            # When lines_descr_xml is set, the block carries XML type metadata
            # for nested TTYP fields so the SDK can discover those types.
            body += _build_lines_descr_block(lines_descr_xml)
            prev_tab = _LINES_DESCR_TRAIL_MARKER   # 0x3c02
            body += _tlv(prev_tab, 0x0201, utf16("X030L_WA"))
            body += _tlv(0x0201, 0x0203, x030l_wa)
            prev_tab = 0x0203

        # DFIES_TAB — row-width 1350 (from DFIES DDIC Unicode layout)
        # Type indicator: 3 on call #1 (no DFIES_WA);
        #                 5 on call #2+ when DFIES_WA is present.
        # Observed from captured SAP NW 7.52 RFCSI DDIF blobs.
        dfies_tab_type = 5 if dfies_wa is not None else 3
        body += _tlv(prev_tab, 0x0301, utf16("DFIES_TAB"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", dfies_tab_type))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", 1350, len(rows)))

        prev = 0x0302
        for row_bytes in rows:
            body += _tlv(prev, 0x0303, row_bytes)
            prev = 0x0303

        # 0x0306 end-of-table terminator — required by the NWRFC SDK to
        # mark the end of DFIES_TAB rows.  Captured from SAP NW 7.52:
        # ...last 0x0305 row → [0x0305][0x0306][0] → [0x0306][0x0301]...
        last = 0x0303 if rows else 0x0302
        body += _tlv(last, 0x0306, b"")

        # FIXED_VALUES — 0 rows; type indicator 4, row-width 166 from captures
        body += _tlv(0x0306, 0x0301, utf16("FIXED_VALUES"))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", 4))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", 166, 0))

        # Program name + footer (from captured DDIF1 blob)
        body += _tlv(0x0302, 0x0130, utf16("SAPLSDIFRUNTIME".ljust(40)))
        body += _tlv(0x0130, 0x0667, b"\x00\x00\x00\x00\x00\x48\x8f\x40")
        body += _tlv(0x0667, 0xffff, b"") + b"\xff\xff"
        return body

    @property
    def tabname_intlength(self):
        return getattr(self.server, "tabname_intlength", {})

    def _get_ddic_fields(self, tabname):
        """Return DFIES field list for *tabname*.

        Lookup order:
        1. ddic_catalog  — exported from SAP (most accurate)
        2. _BUILTIN_DDIC — hand-crafted entries for common types
        3. tabname_intlength index  — synthesise a single RAW field of the
           right total byte length.  Sufficient for empty / output-only
           parameters where the SDK only needs a valid descriptor, not
           individual field names.
        """
        fields = self.ddic_catalog.get(tabname)
        if fields is None:
            fields = _BUILTIN_DDIC.get(tabname)
        if fields is None:
            intlength = self.tabname_intlength.get(tabname, 0)
            if intlength > 0:
                fields = _synthetic_ddic_fields(tabname, intlength)
        return fields

    def _send_ddif_response(self, raw):
        """Send a DDIF_FIELDINFO_GET response.

        Lookup priority:
        1. RFCSI  — served from pre-captured blobs.
        2. ddic_catalog — real DFIES rows built from catalog field data.
        3. _BUILTIN_DDIC — hand-crafted rows for commonly needed structures.
        4. Unknown — zero-row response (SDK won't crash, but can't fill fields).
        """
        session_id = _extract_session_id(raw)
        tabname = self._extract_ddif_tabname(raw)

        if tabname == "RFCSI":
            client = self.server.clients.get(self.client_address)
            if client:
                client.ddif_call_count += 1
                call_num = client.ddif_call_count
            else:
                call_num = 1
            body = get_ddif_body(call_num, session_id)
            self.logger.debug("DDIF_FIELDINFO_GET for RFCSI (call #%d) from %s",
                              call_num, str(self.client_address))
        else:
            # Track per-tabname call count within this session.  The NWRFC SDK
            # calls DDIF twice for the same type.  On call #2+ we include a
            # DFIES_WA scalar export (structure-header descriptor) alongside the
            # same DFIES_TAB rows.  Real SAP servers do the same (see blob 2 vs
            # blob 1 in rfcsi_data.py).  DFIES_WA gives the SDK a single
            # authoritative total INTLEN for the structure so it does not
            # accumulate individual field INTLENs across both calls.
            client = self.server.clients.get(self.client_address)
            if client:
                if not hasattr(client, "ddif_tabname_counts"):
                    client.ddif_tabname_counts = {}
                tn_key = tabname or ""
                client.ddif_tabname_counts[tn_key] = \
                    client.ddif_tabname_counts.get(tn_key, 0) + 1
                tabname_call_num = client.ddif_tabname_counts[tn_key]
            else:
                tabname_call_num = 1

            self.logger.info(
                "DDIF '%s' (call #%d) from %s: processing request",
                tabname or "?", tabname_call_num, str(self.client_address),
            )
            fields = self._get_ddic_fields(tabname) if tabname else None
            if fields:
                # Detect partner codepage so we can send DFIES INTLEN values
                # in the encoding the NWRFC SDK expects.
                # NUC mode (Communication Codepage 1100): SDK reads INTLEN
                # directly as NUC bytes (no halving).  Send NUC values so
                # the SDK's NUC sum matches X030L_WA.TABLEN / PARAMS.INTLENGTH.
                # UC mode (Communication Codepage 4103): SDK halves CHAR
                # INTLEN internally.  Send UC values (unchanged from catalog).
                # Always send UC (catalog) INTLEN values.  UCLEN=1 tells the
                # NUC mode (Comm.CP=1100): send NUC intlen values so SDK reads
                # them directly as NUC bytes.  UCLEN=0 means no Unicode-server
                # uc>=2*nuc structure check, so RAW fields (uc==nuc) pass.
                nuc_mode = (getattr(self, "_partner_codepage", "4103") == "1100")
                # Filter out complex/reference types that the NWRFC SDK cannot
                # parse in flat DFIES rows: 'g' (STRG string-ref, intlen=8) and
                # zero-intlen placeholders (TTYP embedded tables, etc.).
                # Sort by POSITION so the cumulative DFIES offsets match the
                # real ABAP structure layout — avoids misaligned CHAR fields
                # when the catalog CSV is in non-position order.
                # Must match the filter in _nuc_intlength so PARAMS.INTLENGTH ==
                # X030L_WA.TABLEN == sum(NUC contribution from DFIES rows).
                flat_fields = sorted(
                    [
                        f for f in fields
                        if int(f.get("intlen") or 0) > 0
                        and f.get("inttype", "") != "g"
                    ],
                    key=lambda f: int(f.get("position") or 0),
                )
                if len(flat_fields) > _MAX_DDIF_ROWS:
                    intlen_total_full = sum(
                        int(f.get("intlen") or 0) for f in flat_fields
                    )
                    self.logger.info(
                        "DDIF '%s' (call #%d): %d catalog fields exceeds limit %d,"
                        " falling back to synthetic descriptor (intlen_total=%d)",
                        tabname, tabname_call_num, len(flat_fields), _MAX_DDIF_ROWS,
                        intlen_total_full,
                    )
                    flat_fields = _synthetic_ddic_fields(tabname, intlen_total_full)
                dfies_rows = _build_dfies_rows(flat_fields, nuc_mode=nuc_mode)
                intlen_total = sum(int(f.get("intlen") or 0) for f in flat_fields)
                # X030L_WA layout (from queryRecordMetaData reverse-engineering):
                #   queryRecordMetaData calls DDIF twice and packs both
                #   X030L_WA.TABLEN values at metaData+0xd8/+0xdc:
                #     +0xd8 (nucSize) = call #1 X030L_WA TABLEN
                #     +0xdc (ucSize)  = call #2 X030L_WA TABLEN
                #   lock() validates:
                #     field_nuc_end > nucSize → "non-unicode length is too small"
                #     field_uc_end  > ucSize  → same error (different message)
                #   RfcMetaDataBase::add auto-doubles uc_size for RFCTYPE_CHAR:
                #     stored_uc_size = nuc_len * 2  (ignores input uc_len for CHAR)
                #   So:
                #     nuc_total = sum(intlen//2 for CHAR, intlen for RAW)  ← NUC bytes
                #     uc_total  = sum(original UC intlen) = intlen_total   ← UC bytes
                #   Send X030L_WA in BOTH calls:
                #     call #1: TABLEN = nuc_total  → metaData+0xd8
                #     call #2: TABLEN = uc_total   → metaData+0xdc
                nuc_total = sum(
                    int(f.get("intlen") or 0) // 2
                    if f.get("inttype", "") in _UC2_INTTYPES
                    else int(f.get("intlen") or 0)
                    for f in flat_fields
                )
                uc_total = intlen_total  # sum of original UC intlens
                # Call #1: DFIES_TAB + X030L_WA(nuc_total); no DFIES_WA.
                # Call #2+: DFIES_WA + X030L_WA(uc_total) + DFIES_TAB.
                dfies_wa = None
                if tabname_call_num == 1:
                    x030l_wa = _build_x030l_wa_row(tabname, nuc_total)
                else:
                    dfies_wa = _build_dfies_wa_row()
                    x030l_wa = _build_x030l_wa_row(tabname, uc_total)
                # LINES_DESCR: build XML for structures with TTYP fields so
                # the NWRFC SDK can discover and register nested types.
                # The *full* field list (including TTYP/inttype='h' fields
                # filtered out of flat_fields) must be used here.
                # NUC/UC INTLEN values in the XML match the DFIES wire mode.
                lines_descr_xml = _build_lines_descr_xml(
                    tabname, fields, nuc_mode,
                    catalog_fn=self._get_ddic_fields,
                )
                # Table types (e.g. T_MODULE_GENERATE) must send 0 DFIES rows
                # because their LINES_DESCR item 1 names the LINE STRUCTURE
                # (S_MODULE_GENERATE), not the table type itself.  The SDK
                # reads the row structure from LINES_DESCR; sending DFIES rows
                # alongside LINES_DESCR causes the SDK to merge the nested
                # type's fields into the table type's flat layout → overlap.
                # Structures with TTYP fields (e.g. S_MODULE_GENERATE) still
                # send their own DFIES rows; only the nested TTYP entries
                # are described via LINES_DESCR item 2+.
                is_table_type = tabname in _TABLE_TYPE_LINETYPE
                suppress_dfies = is_table_type or (tabname in _SUPPRESS_DFIES_TABNAMES)
                dfies_for_body = [] if suppress_dfies else dfies_rows
                # _SUPPRESS_DFIES_TABNAMES types (e.g. /SLOAE/T_CODE) must
                # send 0 DFIES rows so the SDK does not re-register them as
                # a flat STRU (overriding the TTYP registration from the
                # parent's LINES_DESCR).  X030L_WA and DFIES_WA are still
                # required: real SAP sends X030L_WA(TABLEN=72 NUC / 144 UC)
                # for T_CODE so lock() has a non-zero nucSize to validate
                # against.  LINES_DESCR is already None for these types since
                # they have no TTYP sub-fields.
                body = self._build_ddif_body(session_id, dfies_for_body,
                                             dfies_wa=dfies_wa,
                                             x030l_wa=x030l_wa,
                                             lines_descr_xml=lines_descr_xml)
                source = (
                    "catalog" if tabname in self.ddic_catalog
                    else "builtins" if tabname in _BUILTIN_DDIC
                    else "synthetic"
                )
                extras = ""
                if dfies_wa is not None:
                    extras += " [+DFIES_WA]"
                if x030l_wa is not None:
                    tablen = nuc_total if tabname_call_num == 1 else uc_total
                    extras += " [+X030L_WA tablen=%d]" % tablen
                if lines_descr_xml:
                    extras += " [+LINES_DESCR %dB]" % len(lines_descr_xml)
                skipped = len(fields) - len(flat_fields)
                self.logger.info(
                    "DDIF '%s' (call #%d): %d field(s) from %s%s, "
                    "intlen_total=%d (catalog UC; NUC in wire rows)%s",
                    tabname, tabname_call_num, len(flat_fields), source,
                    (" [%d complex skipped]" % skipped) if skipped else "",
                    intlen_total, extras,
                )
                for f in flat_fields:
                    self.logger.debug(
                        "  DFIES %s.%s: inttype=%s intlen=%s offset=%s",
                        tabname, f.get("fieldname", "?"),
                        f.get("inttype", "?"), f.get("intlen", "?"),
                        f.get("offset", "?"),
                    )
            else:
                body = self._build_ddif_body(session_id)
                self.logger.info(
                    "DDIF '%s' (call #%d): no descriptor found, returning 0 rows",
                    tabname or "?", tabname_call_num,
                )

        if self._gw_connection:
            self.request.send(Raw(self._build_gw_sap_send_hdr(raw) + body))
        else:
            header = self._build_appc_header(raw, len(body))
            self.request.send(Raw(header + body))

    # -- Old-style init (F_SAP_INIT 0xca / F_SAP_ALLOCATE 0xc9) ---------

    def _handle_old_style_init(self, raw, func_type, func_name):
        """Handle F_SAP_INIT/F_SAP_ALLOCATE from older RFC clients."""
        data = {"func_type": func_name}

        try:
            rfc = SAPRFC(raw)

            sap_param = getattr(rfc, "sap_param", None)
            if sap_param and isinstance(sap_param, SAPRFCDTStruct):
                val = _strip_field(getattr(sap_param, "user", None))
                if val:
                    data["user"] = val

            sap_ext = getattr(rfc, "sap_ext_header", None)
            if sap_ext and isinstance(sap_ext, SAPRFCEXTEND):
                val = _strip_field(getattr(sap_ext, "short_dest_name", None))
                if val:
                    data["dest"] = val
        except Exception:
            pass

        self.logger.debug("%s from %s", func_name, str(self.client_address))
        self.session.add_event("APPC old-style init/allocate", data=data)

        try:
            # Respond with acceptance
            resp_func = 0x03 if func_type == 0xc9 else 0x01
            response = SAPRFC(version=0x06, func_type=resp_func, appc_rc=0x00)
            self.request.send(response)
        except error:
            pass


class SAPGatewayServerThreaded(Loggeable, SAPNIServerThreaded):

    clients_cls = SAPGatewayClient
    clients_count = 0

    def __init__(self, server_address, RequestHandlerClass,
                 bind_and_activate=False, socket_cls=None, keep_alive=True,
                 base_cls=None):
        # base_cls=None prevents pysap from auto-decoding NI payloads as
        # SAPRFC.  pysap's SAPRFC parser crashes on F_SAP_SEND packets
        # (codepage_size2 is None → TypeError).  We parse raw bytes instead.
        SAPNIServerThreaded.__init__(self, server_address, RequestHandlerClass,
                                     bind_and_activate, socket_cls, keep_alive,
                                     base_cls=base_cls)


class SAPGatewayService(BaseTCPService):

    server_cls = SAPGatewayServerThreaded
    handler_cls = SAPGatewayServerHandler

    def setup_server(self):
        super(SAPGatewayService, self).setup_server()
        catalog_path = self.config.get("rfm_catalog")
        if catalog_path:
            self.server.rfm_catalog = load_rfm_catalog(catalog_path)
        else:
            self.server.rfm_catalog = {}

        ddic_path = self.config.get("ddic_catalog")
        if ddic_path:
            self.server.ddic_catalog = load_ddic_catalog(ddic_path)
        else:
            self.server.ddic_catalog = {}

        # Build tabname → INTLENGTH index from RFM catalog.
        # Used to synthesise single-RAW-field DFIES descriptors for structure
        # types not present in the catalog or _BUILTIN_DDIC.
        tabname_intlength = {}
        for fm_info in self.server.rfm_catalog.values():
            for p in fm_info.get("params", []):
                tn = (p.get("tabname") or "").strip()
                il = p.get("intlength", 0) or 0
                if tn and il > 0:
                    tabname_intlength[tn] = max(tabname_intlength.get(tn, 0), il)
        self.server.tabname_intlength = tabname_intlength
        self.logger.info(
            "DDIC catalog: %d types loaded; tabname index: %d entries "
            "[RFCPARAM.INTLENGTH: converted to non-unicode via _nuc_intlength]",
            len(self.server.ddic_catalog),
            len(tabname_intlength),
        )
