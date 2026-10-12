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

# Standard imports
import os
import ssl
import tempfile
from datetime import datetime, timedelta, timezone
from hashlib import md5, sha256
from struct import error as struct_error, unpack_from
# External imports
# Custom imports


TLS_HANDSHAKE = 0x16
CLIENT_HELLO = 0x01

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000a
EXT_EC_POINT_FORMATS = 0x000b
EXT_SIGNATURE_ALGORITHMS = 0x000d
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002b

JA4_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
                0x0300: "s3", 0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2",
                0xfefc: "d3"}


def is_grease(value):
    return (value & 0x0f0f) == 0x0a0a and (value >> 8) == (value & 0xff)


def looks_like_tls(data):
    """True if data starts like a TLS handshake record."""
    return len(data) >= 3 and data[0] == TLS_HANDSHAKE and data[1] == 0x03


def _u16_list(data):
    return [unpack_from("!H", data, i)[0] for i in range(0, len(data) - 1, 2)]


def parse_client_hello(data):
    """Parse a TLS ClientHello from the first bytes of a connection.

    Returns a dict with the fields needed for analysis and JA3/JA4
    fingerprints, or None if data is not a (complete enough) ClientHello."""
    if not looks_like_tls(data) or len(data) < 9:
        return None
    record_length = unpack_from("!H", data, 3)[0]
    body = data[5:5 + record_length]
    if len(body) < 4 or body[0] != CLIENT_HELLO:
        return None
    hello_length = int.from_bytes(body[1:4], "big")
    hello = body[4:4 + hello_length]
    try:
        offset = 0
        legacy_version = unpack_from("!H", hello, offset)[0]
        offset += 2 + 32
        session_id_length = hello[offset]
        offset += 1 + session_id_length
        ciphers_length = unpack_from("!H", hello, offset)[0]
        offset += 2
        ciphers = _u16_list(hello[offset:offset + ciphers_length])
        offset += ciphers_length
        compression_length = hello[offset]
        offset += 1 + compression_length
        extensions = []
        if offset + 2 <= len(hello):
            extensions_length = unpack_from("!H", hello, offset)[0]
            offset += 2
            end = min(len(hello), offset + extensions_length)
            while offset + 4 <= end:
                ext_type, ext_length = unpack_from("!HH", hello, offset)
                offset += 4
                extensions.append((ext_type, hello[offset:offset + ext_length]))
                offset += ext_length
    except (IndexError, ValueError, struct_error):
        return None

    result = {
        "record_version": "0x%04x" % unpack_from("!H", data, 1)[0],
        "legacy_version": "0x%04x" % legacy_version,
        "truncated": len(body) < record_length or len(hello) < hello_length,
        "ciphers": list(ciphers),
        "extensions": [e for e, _ in extensions],
        "sni": "",
        "alpn": [],
        "supported_versions": [],
        "supported_groups": [],
        "ec_point_formats": [],
        "signature_algorithms": [],
    }
    for ext_type, ext in extensions:
        try:
            if ext_type == EXT_SERVER_NAME and len(ext) >= 5:
                name_length = unpack_from("!H", ext, 3)[0]
                result["sni"] = ext[5:5 + name_length].decode("ascii", "replace")
            elif ext_type == EXT_ALPN and len(ext) >= 2:
                position = 2
                while position < len(ext):
                    length = ext[position]
                    result["alpn"].append(ext[position + 1:position + 1 + length]
                                          .decode("ascii", "replace"))
                    position += 1 + length
            elif ext_type == EXT_SUPPORTED_VERSIONS and ext:
                result["supported_versions"] = _u16_list(ext[1:1 + ext[0]])
            elif ext_type == EXT_SUPPORTED_GROUPS and len(ext) >= 2:
                result["supported_groups"] = _u16_list(ext[2:])
            elif ext_type == EXT_EC_POINT_FORMATS and ext:
                result["ec_point_formats"] = list(ext[1:1 + ext[0]])
            elif ext_type == EXT_SIGNATURE_ALGORITHMS and len(ext) >= 2:
                result["signature_algorithms"] = _u16_list(ext[2:])
        except (IndexError, ValueError):
            continue

    versions = [v for v in result["supported_versions"] if not is_grease(v)]
    version = max(versions) if versions else legacy_version
    result["version"] = "0x%04x" % version
    result["ja3"], result["ja3_hash"] = ja3(
        legacy_version, ciphers, extensions, result["supported_groups"],
        result["ec_point_formats"])
    result["ja4"] = ja4(version, ciphers, extensions, result["sni"],
                        result["alpn"], result["signature_algorithms"])
    return result


def ja3(version, ciphers, extensions, groups, point_formats):
    fields = [str(version),
              "-".join(str(c) for c in ciphers if not is_grease(c)),
              "-".join(str(e) for e, _ in extensions if not is_grease(e)),
              "-".join(str(g) for g in groups if not is_grease(g)),
              "-".join(str(p) for p in point_formats)]
    text = ",".join(fields)
    return text, md5(text.encode("ascii")).hexdigest()


def _hash12(text):
    if not text:
        return "000000000000"
    return sha256(text.encode("ascii")).hexdigest()[:12]


def ja4(version, ciphers, extensions, sni, alpn, signature_algorithms):
    ciphers = [c for c in ciphers if not is_grease(c)]
    ext_types = [e for e, _ in extensions if not is_grease(e)]
    if alpn and alpn[0]:
        first = alpn[0]
        alpn_code = first[0] + first[-1]
        if not (first[0].isalnum() and first[-1].isalnum()):
            raw = first.encode("ascii", "replace").hex()
            alpn_code = raw[0] + raw[-1]
    else:
        alpn_code = "00"
    part_a = "t%s%s%02d%02d%s" % (JA4_VERSIONS.get(version, "00"),
                                  "d" if sni else "i",
                                  min(len(ciphers), 99), min(len(ext_types), 99),
                                  alpn_code)
    part_b = _hash12(",".join("%04x" % c for c in sorted(ciphers)))
    sorted_ext = ",".join("%04x" % e for e in sorted(ext_types)
                          if e not in (EXT_SERVER_NAME, EXT_ALPN))
    sigs = ",".join("%04x" % s for s in signature_algorithms)
    part_c = _hash12(sorted_ext + ("_" + sigs if sigs else ""))
    return "%s_%s_%s" % (part_a, part_b, part_c)


def generate_certificate(common_name, organization="SAP",
                         units=("SAP Web AS", "INITIAL"), country="DE",
                         issuer_name="SAPNetCA_G2", issuer_locality="Walldorf",
                         days=365, key_size=2048):
    """Generate an SAP-style server certificate and key (PEM bytes).

    Real systems use a certificate issued by the installation's own CA; the
    issuer name is reproduced but the certificate is self-signed."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COUNTRY_NAME, country),
         x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization)] +
        [x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit) for unit in units] +
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.LOCALITY_NAME, issuer_locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
    now = datetime.now(timezone.utc) - timedelta(days=30)
    certificate = (x509.CertificateBuilder()
                   .subject_name(subject)
                   .issuer_name(issuer)
                   .public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now)
                   .not_valid_after(now + timedelta(days=days))
                   .sign(key, hashes.SHA256()))
    return (certificate.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))


def server_context(config, default_common_name):
    """Build the server SSL context for an HTTP service ``tls:`` mapping.

    Uses ``cert_file``/``key_file`` when given, otherwise generates a
    certificate for ``common_name`` at startup."""
    cert_file = config.get("cert_file")
    key_file = config.get("key_file")
    if not cert_file:
        cert, key = generate_certificate(config.get("common_name", default_common_name))
        directory = tempfile.mkdtemp(prefix="honeysap-tls-")
        cert_file = os.path.join(directory, "cert.pem")
        key_file = os.path.join(directory, "key.pem")
        with open(cert_file, "wb") as f:
            f.write(cert)
        with open(os.open(key_file, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
            f.write(key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.set_alpn_protocols(["http/1.1"])
    if config.get("request_client_cert", True):
        # Ask for a client certificate like the ICM does; only clients holding
        # a certificate of the advertised CA will send one.
        context.verify_mode = ssl.CERT_OPTIONAL
        context.load_verify_locations(cafile=cert_file)
    return context
