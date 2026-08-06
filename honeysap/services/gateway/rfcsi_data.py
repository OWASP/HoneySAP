# HoneySAP - SAP low-interaction honeypot
#
# Pre-built DDIF_FIELDINFO_GET response bodies for the RFCSI structure.
# Captured from SAP NW 7.52.  Session ID at body bytes 16-31 is zeroed
# and must be patched with the real session ID at runtime.
#
# These describe the 20 fields of the RFCSI structure so that the NWRFC
# SDK can deserialize RFC_SYSTEM_INFO responses into named fields.

import zlib
import base64


def _decode(b64):
    return zlib.decompress(base64.b64decode(b64))


_DDIF1 = (
    "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"
)

_DDIF2 = (
    "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"
    "QrP/eNYlgBL05q8BwK7ybwS9V1cBWF39CZkuqI0="
)

_DDIF3 = (
    "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"
    "xacuEMDbA4C58IMCARwOABzOT+9+rFQ="
)


# Ordered list of response bodies for sequential DDIF calls.
_BODIES = [_decode(_DDIF1), _decode(_DDIF2), _decode(_DDIF3)]


def get_ddif_body(call_number, session_id):
    """Return the DDIF_FIELDINFO_GET response body for the given call.

    The NWRFC SDK makes up to 3 DDIF calls when resolving a structure
    type.  *call_number* is 1-based.  The 16-byte *session_id* is
    patched into bytes 16-31 of the body.
    """
    idx = min(call_number - 1, len(_BODIES) - 1)
    body = bytearray(_BODIES[idx])
    body[16:32] = session_id[:16]
    return bytes(body)
