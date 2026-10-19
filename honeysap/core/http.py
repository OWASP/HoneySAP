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

"""HTTP front end shared by the HTTP services.

Reads requests from the raw socket so the exact bytes, all headers in their
original order and case, the body, TLS ClientHellos and non-HTTP input can be
logged before a service (or its WSGI application) answers them."""

# Standard imports
import re
import socket
import ssl
from socketserver import BaseRequestHandler, ThreadingMixIn, TCPServer
from time import monotonic
# External imports
# Custom imports
from . import http_analysis
from .evidence import WireTap, connection_closed
from .logger import Loggeable
from .tls import looks_like_tls, parse_client_hello


REQUEST_LINE = re.compile(
    rb"^([!#$%&'*+.^_`|~0-9A-Za-z-]+) (\S+) HTTP/(\d)\.(\d)\r?\n$")
MAX_REQUEST_LINE = 65536
MAX_HEADER_BYTES = 65536
MAX_HEADERS = 200


class HTTPRequest(object):
    """An HTTP request as received on the wire."""

    def __init__(self, method, target, version, headers, body, raw,
                 scheme="http"):
        self.method = method
        self.target = target
        self.version = version
        self.headers = headers
        self.body = body
        self.raw = raw
        self.scheme = scheme
        path, _, query = target.partition("?")
        self.path = path
        self.query = query

    def header(self, name, default=None):
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return default

    @property
    def keep_alive(self):
        connection = (self.header("Connection") or "").lower()
        if self.version >= "HTTP/1.1":
            return "close" not in connection
        return "keep-alive" in connection


class HTTPResponse(object):
    """An HTTP response with headers kept in the given order and case."""

    def __init__(self, status=200, reason="OK", headers=None, body=b"",
                 version="HTTP/1.1", close=False):
        self.status = status
        self.reason = reason
        self.headers = list(headers or [])
        self.body = body
        self.version = version
        self.close = close

    def to_bytes(self):
        head = "%s %d %s\r\n" % (self.version, self.status, self.reason)
        head += "".join("%s: %s\r\n" % (name, value) for name, value in self.headers)
        return head.encode("latin-1", "replace") + b"\r\n" + self.body


class NonHTTPInput(Exception):
    """Received data that is not an HTTP request."""

    def __init__(self, kind, raw):
        super(NonHTTPInput, self).__init__(kind)
        self.kind = kind
        self.raw = raw


class HTTPParseError(Exception):
    """An HTTP request that could not be parsed completely."""

    def __init__(self, stage, message, raw):
        super(HTTPParseError, self).__init__(message)
        self.stage = stage
        self.raw = raw


class RequestReader(object):
    """Buffered reader keeping the raw bytes of the current request."""

    def __init__(self, sock, max_body_bytes):
        self.sock = sock
        self.buffer = b""
        self.raw = bytearray()
        self.max_body_bytes = max_body_bytes

    def _fill(self):
        data = self.sock.recv(65536)
        if not data:
            raise EOFError()
        self.buffer += data
        return data

    def _take(self, length):
        data, self.buffer = self.buffer[:length], self.buffer[length:]
        self.raw += data
        return data

    def readline(self, limit):
        while b"\n" not in self.buffer:
            if len(self.buffer) >= limit:
                raise ValueError("line too long")
            self._fill()
        return self._take(self.buffer.index(b"\n") + 1)

    def read(self, length):
        while len(self.buffer) < length:
            self._fill()
        return self._take(length)

    def take_raw(self):
        data, self.raw = bytes(self.raw), bytearray()
        return data

    def pending(self):
        """Bytes received but not consumed by a request (reported as raw
        input when the connection ends in the middle of a request)."""
        return bytes(self.raw) + self.buffer

    def read_request(self, scheme="http"):
        """Read the next request. Returns None on a clean close before any
        byte of a new request."""
        self.raw = bytearray()
        if not self.buffer:
            try:
                self._fill()
            except EOFError:
                return None
        if looks_like_tls(self.buffer):
            raise NonHTTPInput("tls", self.buffer)
        try:
            line = self.readline(MAX_REQUEST_LINE)
        except ValueError:
            raise NonHTTPInput("invalid_request_line", self.pending())
        match = REQUEST_LINE.match(line)
        if not match:
            raise NonHTTPInput("invalid_request_line", self.pending())
        method = match.group(1).decode("ascii")
        target = match.group(2).decode("latin-1")
        version = "HTTP/%s.%s" % (match.group(3).decode(), match.group(4).decode())

        headers = []
        header_bytes = 0
        while True:
            try:
                line = self.readline(MAX_HEADER_BYTES)
            except ValueError:
                raise HTTPParseError("headers", "header line too long", self.pending())
            header_bytes += len(line)
            if line in (b"\r\n", b"\n"):
                break
            if header_bytes > MAX_HEADER_BYTES or len(headers) >= MAX_HEADERS:
                raise HTTPParseError("headers", "too many headers", self.pending())
            name, colon, value = line.decode("latin-1").partition(":")
            if not colon or not name or name != name.strip():
                raise HTTPParseError("headers", "malformed header line", self.pending())
            headers.append((name, value.strip()))

        request = HTTPRequest(method, target, version, headers, b"", b"",
                              scheme=scheme)
        transfer_encoding = (request.header("Transfer-Encoding") or "").lower()
        if "chunked" in transfer_encoding:
            request.body = self._read_chunked()
        elif request.header("Content-Length") is not None:
            try:
                length = int(request.header("Content-Length"))
                if length < 0:
                    raise ValueError()
            except ValueError:
                raise HTTPParseError("body", "invalid Content-Length", self.pending())
            if length > self.max_body_bytes:
                raise HTTPParseError("body", "body too large", self.pending())
            request.body = self.read(length)
        request.raw = self.take_raw()
        return request

    def _read_chunked(self):
        body = bytearray()
        while True:
            try:
                size_line = self.readline(4096)
                size = int(size_line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                raise HTTPParseError("body", "invalid chunk size", self.pending())
            if size == 0:
                break
            if len(body) + size > self.max_body_bytes:
                raise HTTPParseError("body", "body too large", self.pending())
            body += self.read(size)
            self.readline(4096)
        # Trailer section
        while True:
            line = self.readline(MAX_HEADER_BYTES)
            if line in (b"\r\n", b"\n"):
                break
        return bytes(body)


class HTTPServerThreaded(ThreadingMixIn, TCPServer):
    daemon_threads = True


class HTTPConnectionHandler(Loggeable, BaseRequestHandler):
    """Handle one client connection of an HTTP service."""

    def setup(self):
        self.service = self.server.server
        self.policy = self.service.logging_policy
        self.started = monotonic()
        self.requests = 0
        self.close_reason = None
        sock = getattr(self.request, "ins", self.request)
        self.tap = WireTap(sock)
        client_ip, client_port = self.client_address[:2]
        server_ip, server_port = self.server.server_address[:2]
        self.session = self.server.session_manager.get_session(
            self.service.session_service_name, client_ip, client_port,
            server_ip, server_port)
        self.session.connection_id = self.tap.connection_id
        self.session.logging_policy = self.policy
        timeout = self.service.config.get("timeout", 30)
        try:
            self.tap.settimeout(timeout)
        except (AttributeError, OSError):
            pass
        self.scheme = "http"
        self.stream = self.tap
        self.reader = None
        self.secure = None
        if self.policy.connection_events == "all":
            self.session.add_event("Connection opened",
                                   data={"client": str(self.client_address)})

    def handle(self):
        try:
            if self.service.tls_context is not None and not self.start_tls():
                return
            self.reader = RequestReader(self.stream, self.service.max_body_bytes)
            while True:
                try:
                    request = self.reader.read_request(self.scheme)
                except NonHTTPInput as error:
                    self.handle_non_http(error.kind, error.raw)
                    return
                except HTTPParseError as error:
                    self.handle_parse_error(error)
                    return
                if request is None:
                    self.close_reason = "client_close"
                    return
                self.requests += 1
                if not self.handle_http(request):
                    return
        except socket.timeout:
            self.close_reason = "timeout"
            self.report_pending()
        except (EOFError, ConnectionError, ssl.SSLError, OSError):
            self.close_reason = "client_close"
            self.report_pending()

    def report_pending(self):
        """Report bytes of an incomplete request when the connection ends."""
        if self.reader is None:
            return
        pending = self.reader.pending()
        if pending:
            kind = "incomplete_request" if REQUEST_LINE.match(
                pending.split(b"\n", 1)[0] + b"\n") else "incomplete_input"
            self.log_non_http(kind, pending)

    def start_tls(self):
        """Log the ClientHello and wrap the connection with TLS."""
        try:
            peeked = self.tap.recv(16384, socket.MSG_PEEK)
        except socket.timeout:
            self.close_reason = "timeout"
            return False
        if not peeked:
            self.close_reason = "client_close"
            return False
        if not looks_like_tls(peeked):
            # The ICM closes TLS ports silently on plaintext input
            data = self.tap.recv(65536)
            self.log_non_http("plaintext_on_tls_port", data)
            self.close_reason = "server_close"
            return False
        tls = parse_client_hello(peeked)
        self.session.add_event("TLS client hello", data={"tls": tls},
                               request=peeked)
        sock = self.tap._sock
        if isinstance(sock, WireTap) or not isinstance(sock, socket.socket):
            self.close_reason = "error"
            return False
        try:
            secure = self.service.tls_context.wrap_socket(sock, server_side=True)
        except (ssl.SSLError, OSError) as error:
            self.session.add_event("TLS handshake failed",
                                   data={"error": "%s: %s" % (type(error).__name__, error)})
            self.close_reason = "error"
            return False
        # wrap_socket detaches the original socket: this one must be closed
        self.secure = secure
        tap = WireTap(secure)
        tap.connection_id = self.tap.connection_id
        tap.bytes_in, tap.bytes_out = self.tap.bytes_in, self.tap.bytes_out
        self.tap = self.stream = tap
        self.scheme = "https"
        peer = secure.getpeercert()
        data = {"version": secure.version(),
                "cipher": (secure.cipher() or ("",))[0],
                "alpn": secure.selected_alpn_protocol() or ""}
        if peer:
            data["client_certificate"] = peer
        self.session.add_event("TLS established", data=data)
        return True

    def log_non_http(self, kind, raw, sent=None):
        data = {"kind": kind}
        tls = parse_client_hello(raw) if looks_like_tls(raw) else None
        if tls is not None:
            data["tls"] = tls
        self.session.add_event("Non-HTTP input", data=data, request=raw,
                               response=sent if self.policy.response_events else None)

    def handle_non_http(self, kind, raw):
        response = self.service.non_http_response(kind)
        sent = self.send(response) if response is not None else None
        self.log_non_http(kind, raw, sent)
        self.close_reason = "server_close"

    def handle_parse_error(self, error):
        response = self.service.bad_request_response(error)
        sent = self.send(response) if response is not None else None
        if self.policy.unparsed_input:
            self.session.add_event("Unparsed input",
                                   data={"stage": error.stage,
                                         "error": str(error),
                                         "service_state": {"requests": self.requests}},
                                   request=error.raw,
                                   response=sent if self.policy.response_events else None)
        self.close_reason = "server_close"

    def send(self, response):
        data = response.to_bytes() if isinstance(response, HTTPResponse) else response
        self.stream.sendall(data)
        return data

    def handle_http(self, request):
        """Answer one request and log it. Returns False to close."""
        try:
            response = self.service.handle_request(request, self)
        except Exception as error:
            self.logger.exception("Error handling HTTP request")
            if self.policy.unparsed_input:
                self.session.add_event("Unparsed input",
                                       data={"stage": "handle_request",
                                             "error": "%s: %s" % (type(error).__name__, error),
                                             "service_state": {"requests": self.requests}},
                                       request=request.raw)
            response = self.service.internal_error_response(request)
        keep_alive = (request.keep_alive and response is not None and
                      not response.close)
        sent = self.send(response) if response is not None else b""
        self.log_request(request, response, sent)
        if not keep_alive:
            self.close_reason = "server_close"
        return keep_alive

    def log_request(self, request, response, sent):
        if not self.service.should_log(request):
            return
        data = {"method": request.method,
                "target": request.target,
                "path": request.path,
                "query": request.query,
                "http_version": request.version,
                "scheme": request.scheme,
                "host": request.header("Host", ""),
                "user_agent": request.header("User-Agent", ""),
                "body_size": len(request.body),
                "status": response.status if response is not None else None}
        if self.policy.http_headers:
            data["headers"] = [[name, value] for name, value in request.headers]
        if self.policy.http_body and request.body:
            data["body"] = request.body[:self.policy.max_payload_bytes or None]
            if self.policy.max_payload_bytes and len(request.body) > self.policy.max_payload_bytes:
                data["body_truncated"] = True
        self.analyze(request, data)
        data.update(self.service.request_details(request))
        self.session.add_event(self.service.request_event_name, data=data,
                               request=request.raw,
                               response=sent if self.policy.response_events else None)

    def analyze(self, request, data):
        """Decoded parameters, uploads, credentials, forwarding headers and
        attack pattern tags of a request."""
        parts = http_analysis.multipart_parts(request)
        if parts is not None:
            data["multipart"] = parts
        if self.policy.http_params:
            params = http_analysis.query_params(request)
            if params:
                data["query_params"] = params
            form = http_analysis.form_params(request, parts)
            if form:
                data["form_params"] = form
            parsed = http_analysis.json_body(request, self.policy.max_payload_bytes or 1 << 20)
            if parsed is not None:
                data["json_body"] = parsed
            submitted = http_analysis.credentials(params + form)
            if submitted and not getattr(request, "credentials_logged", False):
                submitted.update({"path": request.path, "method": request.method})
                self.session.add_event("HTTP credentials submitted", data=submitted)
        forwarded = http_analysis.forwarded_for(request)
        if forwarded:
            data["forwarded_for"] = forwarded
        data["tags"] = http_analysis.tags(request, parts)

    def finish(self):
        if self.secure is not None:
            try:
                # Send close_notify before closing
                self.secure.settimeout(1)
                self.secure.unwrap().close()
            except (OSError, ValueError):
                pass
            try:
                self.secure.close()
            except OSError:
                pass
        if self.policy.connection_events != "none":
            connection_closed(self.session, self.client_address, self.started,
                              self.tap, self.requests, self.close_reason)
