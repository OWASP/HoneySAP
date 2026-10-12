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
import socket
from time import monotonic
from uuid import uuid4
# External imports
# Custom imports


CONNECTION_EVENTS = ("none", "close", "all")


class LoggingPolicy(object):
    """Evidence logging flags for one service.

    Built from the top-level ``logging:`` mapping, overridden key by key by a
    service's own ``logging:`` mapping."""

    defaults = {
        # Keep the bytes received/sent on the wire in request/response
        "raw_payloads": True,
        # Emit a "Sent packet" event with the bytes sent for each request
        "response_events": True,
        # Cap for each request/response field; 0 disables the cap
        "max_payload_bytes": 65536,
        # Connection lifecycle events: none, close or all (open and close)
        "connection_events": "close",
        # Emit "Unparsed input" when received data cannot be handled
        "unparsed_input": True,
        # HTTP services: log all request headers in order
        "http_headers": True,
        # HTTP services: log the request body (also part of the raw request)
        "http_body": True,
    }

    def __init__(self, **options):
        values = dict(self.defaults)
        unknown = set(options) - set(values)
        if unknown:
            raise ValueError("Unknown logging option(s): %s" %
                             ", ".join(sorted(unknown)))
        values.update(options)
        for name in ("raw_payloads", "response_events", "unparsed_input",
                     "http_headers", "http_body"):
            if not isinstance(values[name], bool):
                raise ValueError("logging.%s must be a boolean" % name)
        limit = values["max_payload_bytes"]
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise ValueError("logging.max_payload_bytes must be a non-negative integer")
        if values["connection_events"] is False:
            values["connection_events"] = "none"
        if values["connection_events"] not in CONNECTION_EVENTS:
            raise ValueError("logging.connection_events must be one of: %s" %
                             ", ".join(CONNECTION_EVENTS))
        self.__dict__.update(values)

    @classmethod
    def from_config(cls, config):
        options = config.get("logging") or {}
        if not isinstance(options, dict):
            raise ValueError("logging must be a mapping")
        return cls(**options)

    def payload(self, value):
        """Return (payload, original_size, truncated) for a request/response
        field according to the policy. Non-bytes values pass unchanged."""
        if not isinstance(value, (bytes, bytearray, memoryview)):
            return value, None, False
        value = bytes(value)
        size = len(value)
        if not self.raw_payloads:
            return None, size, False
        if self.max_payload_bytes and size > self.max_payload_bytes:
            return value[:self.max_payload_bytes], size, True
        return value, size, False


class WireTap(object):
    """Socket proxy recording the bytes received and sent on a connection."""

    def __init__(self, sock):
        self._sock = sock
        # A connection handed over to another service (SAPRouter routes) is
        # still the same TCP connection
        self.connection_id = getattr(sock, "connection_id", None) or uuid4()
        self.rx = bytearray()
        self.tx = bytearray()
        self.bytes_in = 0
        self.bytes_out = 0

    def __getattr__(self, name):
        return getattr(self._sock, name)

    def recv(self, bufsize, flags=0):
        data = self._sock.recv(bufsize, flags)
        if flags & socket.MSG_PEEK:
            return data
        self.rx += data
        self.bytes_in += len(data)
        return data

    def send(self, data, *args, **kwargs):
        sent = self._sock.send(data, *args, **kwargs)
        self.tx += bytes(data)[:sent]
        self.bytes_out += sent
        return sent

    def sendall(self, data, *args, **kwargs):
        result = self._sock.sendall(data, *args, **kwargs)
        self.tx += bytes(data)
        self.bytes_out += len(data)
        return result

    def take_rx(self):
        data, self.rx = bytes(self.rx), bytearray()
        return data

    def take_tx(self):
        data, self.tx = bytes(self.tx), bytearray()
        return data


def install_tap(stream):
    """Install a WireTap on a scapy stream socket and return it. The tap is
    placed on the underlying socket so every byte read or written by the
    stream (framing, keep-alives) is recorded. Taps nest: a routed handler
    counts its own traffic while the router's tap keeps the total."""
    sock = getattr(stream, "ins", None)
    if sock is None:
        return None
    sock = WireTap(sock)
    stream.ins = sock
    if getattr(stream, "outs", None) is not None:
        stream.outs = sock
    return sock


def connection_closed(session, client_address, started, tap, packets_in,
                      close_reason):
    """Emit the "Connection closed" summary event of a connection."""
    session.add_event("Connection closed", data={
        "client": str(client_address),
        "duration_seconds": round(monotonic() - started, 3),
        "bytes_in": tap.bytes_in if tap else 0,
        "bytes_out": tap.bytes_out if tap else 0,
        "packets_in": packets_in,
        "close_reason": close_reason or "server_close"})


def summarize(packet):
    try:
        return packet.summary()
    except Exception:
        return type(packet).__name__


class EvidenceHandlerMixin(object):
    """Raw evidence capture for SAP NI request handlers.

    Records the exact bytes of every received packet ("Received packet") and
    of the bytes sent in response ("Sent packet"), reports input that fails to
    decode or handle ("Unparsed input") and the connection lifecycle
    ("Connection opened"/"Connection closed")."""

    tap = None
    raw_request = None
    close_reason = None

    @property
    def logging_policy(self):
        server = getattr(self, "server", None)
        policy = getattr(server, "logging_policy", None)
        if policy is None:
            policy = LoggingPolicy.from_config(getattr(server, "config", None) or {})
            if server is not None:
                server.logging_policy = policy
        return policy

    def setup(self):
        super(EvidenceHandlerMixin, self).setup()
        self.connection_started = monotonic()
        self.packets_in = 0
        self.close_reason = None
        self.tap = install_tap(self.request)
        self.session.connection_id = self.tap.connection_id if self.tap else uuid4()
        self.session.logging_policy = self.logging_policy
        if self.logging_policy.connection_events == "all":
            self.session.add_event("Connection opened",
                                   data={"client": str(self.client_address)})

    def handle(self):
        while not self.closed.is_set():
            try:
                if not self.receive_packet():
                    break
                self.handle_data()
            except Exception as error:
                self.record_unparsed(error, "handle_data")
                self.close_reason = "error"
                break
            finally:
                self.flush_sent()
        if self.close_reason is None:
            self.close_reason = "server_close"

    def receive_packet(self):
        """Receive the next packet into ``self.packet``, emitting the raw
        evidence events. Returns False if the connection must end."""
        if self.tap is not None:
            self.tap.take_rx()
        try:
            self.packet = self.request.recv()
        except socket.timeout:
            self.close_reason = "timeout"
            self.record_partial_input("recv")
            return False
        except (socket.error, EOFError):
            self.close_reason = "client_close"
            self.record_partial_input("recv")
            return False
        except Exception as error:
            self.close_reason = "error"
            self.record_unparsed(error, "decode")
            return False

        self.packets_in += 1
        raw = self.tap.take_rx() if self.tap is not None else b""
        if not raw:
            try:
                raw = bytes(self.packet)
            except Exception:
                raw = b""
        self.raw_request = raw
        self.session.add_event("Received packet",
                               data={"summary": summarize(self.packet)},
                               request=raw)
        return True

    def record_partial_input(self, stage):
        """Report bytes received before the connection ended mid-packet."""
        raw = self.tap.take_rx() if self.tap is not None else b""
        if raw:
            self.record_unparsed(None, stage, raw=raw)

    def record_unparsed(self, error, stage, raw=None):
        if not self.logging_policy.unparsed_input:
            return
        if raw is None:
            raw = self.tap.take_rx() if self.tap is not None else b""
            raw = raw or self.raw_request or b""
        data = {"stage": stage,
                "service_state": self.service_state()}
        if error is not None:
            data["error"] = "%s: %s" % (type(error).__name__, error)
        self.session.add_event("Unparsed input", data=data, request=raw)

    def service_state(self):
        """Protocol state reported with unparsed input, for subclasses."""
        return {"packets_in": getattr(self, "packets_in", 0)}

    def flush_sent(self):
        if self.tap is None:
            return
        sent = self.tap.take_tx()
        if sent and self.logging_policy.response_events:
            self.session.add_event("Sent packet", response=sent)

    def finish(self):
        try:
            super(EvidenceHandlerMixin, self).finish()
        finally:
            self.flush_sent()
            if self.logging_policy.connection_events != "none":
                connection_closed(self.session, self.client_address,
                                  getattr(self, "connection_started", monotonic()),
                                  self.tap, getattr(self, "packets_in", 0),
                                  self.close_reason)
