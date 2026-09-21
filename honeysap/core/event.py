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
import json
import math
from base64 import b64encode
from datetime import date, datetime, timezone
from uuid import uuid4
# External imports

# Custom imports


class Event(object):
    """An object representing an attack session event"""

    # This is the first explicit event schema; older event consumers had no
    # schema contract to preserve.
    schema_version = 1

    def __init__(self, event, data=None, request=None, response=None,
                 session=None):
        self.event = event
        self.data = data
        self.request = request
        self.response = response
        self.session = session
        self.uuid = uuid4()
        self.sequence = None
        self.timestamp = datetime.now(timezone.utc)

    def __str__(self):
        if self.session is None:
            raise Exception("Event not attached to a session")
        return "<Event '%s' at %s in session '%s'>" % (self.event, self.timestamp, self.session.uuid)

    @staticmethod
    def _encode_field(value):
        """Encode a request/response field for JSON serialization."""
        if not value:
            return ""
        if isinstance(value, str):
            value = value.encode("utf-8", errors="replace")
        try:
            return b64encode(bytes(value)).decode("ascii")
        except (TypeError, ValueError):
            return b64encode(Event._safe_repr(value).encode("utf-8",
                                                            errors="replace")).decode("ascii")

    @staticmethod
    def _safe_repr(value):
        try:
            return repr(value)
        except Exception:
            return "<unrepresentable %s>" % type(value).__name__

    @staticmethod
    def _serialize_data(data):
        """Make event data JSON-serializable."""
        if data is None:
            return ""
        if isinstance(data, (bytes, bytearray, memoryview)):
            return {"type": "bytes", "encoding": "base64",
                    "value": b64encode(data).decode("ascii")}
        if isinstance(data, dict):
            if all(isinstance(key, str) for key in data):
                return {key: Event._serialize_data(value)
                        for key, value in data.items()}
            return {"type": "mapping", "items": [
                {"key": Event._serialize_data(key),
                 "value": Event._serialize_data(value)}
                for key, value in data.items()]}
        if isinstance(data, (list, tuple)):
            return [Event._serialize_data(v) for v in data]
        if isinstance(data, set):
            return {"type": "set", "items": [Event._serialize_data(value)
                                                  for value in sorted(data,
                                                                      key=Event._safe_repr)]}
        if isinstance(data, (datetime, date)):
            return {"type": type(data).__name__, "value": data.isoformat()}
        if isinstance(data, float) and not math.isfinite(data):
            return {"type": "float", "value": str(data)}
        if isinstance(data, (str, int, float, bool)) or data is None:
            return data
        return {"type": "repr",
                "class": "%s.%s" % (type(data).__module__, type(data).__name__),
                "value": Event._safe_repr(data)}

    def __repr__(self):
        if self.session is None:
            raise Exception("Event not attached to a session")
        return json.dumps({"schema_version": self.schema_version,
                           "event_id": str(self.uuid),
                           "sequence": self.sequence,
                           "session": str(self.session.uuid),
                           "campaign": str(self.session.campaign_uuid),
                           "parent_session": (
                               str(self.session.parent_session_uuid)
                               if self.session.parent_session_uuid else ""),
                           "event": self.event,
                           "data": self._serialize_data(self.data),
                           "request": self._encode_field(self.request),
                           "response": self._encode_field(self.response),
                           "service": self.session.service,
                           "source_ip": self.session.source_ip,
                           "source_port": self.session.source_port,
                           "target_ip": self.session.target_ip,
                           "target_port": self.session.target_port,
                           "timestamp": self.timestamp.isoformat()}, allow_nan=False)
