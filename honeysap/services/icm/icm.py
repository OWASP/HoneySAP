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
import re
import os
from base64 import b64decode
from binascii import Error as Base64Error
from datetime import datetime, timezone
from email.utils import formatdate
from random import getrandbits, randint
from urllib.parse import parse_qs
# External imports
# Custom imports
from http.client import responses as HTTP_REASONS
from honeysap.core.http import HTTPResponse
from honeysap.core.service import BaseHTTPService
from honeysap.services.icm.flp import FioriLaunchpad


TEMPLATES = os.path.join(os.path.dirname(__file__), "templates")

# Internet Communication Framework (ICF) services by path prefix. Values:
#   ping, info, icman_ping, logoff, icm_admin: built-in public services
#   auth: active service requiring a logon (401, credentials are logged)
#   inactive: deactivated service (403)
#   not_found: no service (404)
DEFAULT_ICF = {
    "/sap/public/ping": "ping",
    "/sap/public/info": "info",
    "/sap/public/icman/ping": "icman_ping",
    "/sap/public/bc/icf/logoff": "logoff",
    "/sap/admin/public": "icm_admin",
    "/sap/bc/soap": "auth",
    "/sap/bc/srt": "auth",
    "/sap/bc/adt": "auth",
    "/sap/bc/gui/sap/its": "auth",
    "/sap/bc/bsp": "auth",
    "/sap/bc/webdynpro": "auth",
    "/sap/bc/ui5_ui5": "auth",
    "/sap/bc/ui2": "auth",
    "/sap/bc/lrep": "auth",
    "/sap/bc/rest": "auth",
    "/sap/opu": "auth",
    "/sap/es": "auth",
    "/sap/bc/ping": "inactive",
    "/sap/bc/echo": "inactive",
    "/sap/bc/error": "inactive",
    "/sap/bc/icf/info": "inactive",
}

ICF_HANDLERS = ("ping", "info", "icman_ping", "logoff", "icm_admin", "auth",
                "inactive", "not_found")

# Texts of the logon error page by logon language
LOGON_FAILED_TEXTS = {
    "EN": ("Logon failed", "401 Not authorized"),
    "DE": ("Anmeldung fehlgeschlagen", "401 Nicht autorisiert"),
}


def _read_template(name):
    with open(os.path.join(TEMPLATES, name), "rb") as f:
        return f.read()


def _perf_fesrec():
    # Server processing time in microseconds
    return "%d.000000" % randint(500, 4000)


class SAPICMService(BaseHTTPService):

    default_port = 8000
    default_release = 720
    session_service_name = "icm_http"
    request_event_name = "ICM HTTP request"

    def setup_server(self):
        self.bad_request_page = _read_template("icm_bad_request.html")
        self.error_page = _read_template("icm_error.html")
        self.logon_failed_page = _read_template("icm_error_401.html")
        self.logoff_page = _read_template("icf_logoff.html")
        icf = dict(DEFAULT_ICF)
        icf.update(self.config.get("icf") or {})
        for path, handler in icf.items():
            if handler not in ICF_HANDLERS:
                raise ValueError("Unknown ICF handler '%s' for %s" % (handler, path))
        # Longest prefix first
        self.icf = sorted(((path.lower().rstrip("/"), handler)
                           for path, handler in icf.items()),
                          key=lambda item: len(item[0]), reverse=True)
        super(SAPICMService, self).setup_server()
        flp = self.config.get("fiori_launchpad") or {}
        self.flp = FioriLaunchpad(self, flp) if flp.get("enabled", False) else None

    # Request dispatching

    def resolve(self, path):
        """Find the ICF handler of a path (case-insensitive, by segment)."""
        path = path.lower()
        for prefix, handler in self.icf:
            if path == prefix or path.startswith(prefix + "/"):
                return handler, prefix
        return "not_found", None

    def handle_request(self, request, connection):
        handler, _ = self.resolve(request.path)
        if self.flp is not None and handler not in ("ping", "info", "icman_ping", "logoff",
                                                    "icm_admin", "inactive") and \
           self.flp.handles(request):
            response = self.flp.handle(request, connection)
        else:
            response = getattr(self, "icf_%s" % handler)(request, connection)
        if request.method == "HEAD":
            response.body = b""
        if not request.keep_alive:
            response.close = True
        if response.close and request.header("Connection") is not None and \
           request.version >= "HTTP/1.1" and \
           not any(name.lower() == "connection" for name, _ in response.headers):
            response.headers.append(("connection", "close"))
        return response

    def should_log(self, request):
        """Static launchpad resources are only logged with static_assets."""
        if self.flp is not None and not self.logging_policy.static_assets and \
           self.flp.handles(request) and self.flp.is_static(request):
            return False
        return True

    def request_details(self, request):
        handler, prefix = self.resolve(request.path)
        if self.flp is not None and self.flp.handles(request):
            handler = "fiori_launchpad"
        details = {"icf_handler": handler}
        if prefix:
            details["icf_service"] = prefix
        if self.flp is not None and handler == "fiori_launchpad":
            session = self.flp.session(request)
            if session is not None:
                # Actions of a logged on launchpad user
                details["flp_user"] = session.user
                details["flp_client"] = session.client
        credentials = self.basic_credentials(request)
        if credentials is not None:
            details["auth_user"], details["auth_password"] = credentials
        return details

    # Helpers

    def query(self, request):
        return {key.lower(): values[-1] for key, values in
                parse_qs(request.query, keep_blank_values=True).items()}

    def client(self, request, value=None):
        """Client of a request; values that are not a client number are
        ignored like a missing one."""
        value = value if value is not None else self.query(request).get("sap-client")
        return value if value and re.fullmatch(r"\d{3}", value) else self.persona.client

    def logon_language(self, request):
        language = self.query(request).get("sap-language")
        if not language:
            accept = request.header("Accept-Language")
            if accept:
                language = accept.split(",")[0].split("-")[0].strip()
        return (language or self.persona.language).upper()

    def usercontext_cookie(self, request):
        context = "sap-client=%s" % self.client(request)
        language = self.query(request).get("sap-language")
        if language:
            context = "sap-language=%s&%s" % (language.upper(), context)
        return ("set-cookie", "sap-usercontext=%s; path=/" % context)

    def basic_credentials(self, request):
        authorization = request.header("Authorization") or ""
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() != "basic":
            return None
        try:
            decoded = b64decode(value.strip(), validate=True).decode("latin-1")
        except (Base64Error, ValueError):
            return ("", value.strip())
        user, _, password = decoded.partition(":")
        return (user, password)

    @staticmethod
    def reason(status):
        return HTTP_REASONS.get(status, "Unknown")

    def response(self, request, status, reason, headers, body):
        version = "HTTP/1.0" if request.version < "HTTP/1.1" else "HTTP/1.1"
        return HTTPResponse(status, reason, headers, body, version=version)

    def error_response(self, request, status, reason, status_text, sap_system=False):
        body = (self.error_page
                .replace(b"{{STATUS_TEXT}}", status_text.encode("utf-8"))
                .replace(b"{{YEAR}}", str(datetime.now(timezone.utc).year).encode()))
        headers = [("content-type", "text/html; charset=utf-8"),
                   ("content-length", str(len(body)))]
        if sap_system:
            # Logon related errors come from the ICF logon handler
            headers = [self.usercontext_cookie(request)] + headers + [
                ("sap-authenticated", "false"), ("sap-system", self.persona.sid),
                ("sap-server", "true")]
        else:
            headers += [("sap-server", "true"), ("sap-authenticated", "false")]
        headers.append(("sap-perf-fesrec", _perf_fesrec()))
        return self.response(request, status, reason, headers, body)

    # ICF handlers

    def icf_not_found(self, request, connection):
        return self.error_response(request, 404, "Not found", "404 Not found")

    def icf_inactive(self, request, connection):
        return self.error_response(request, 403, "Forbidden", "403 Forbidden")

    def icf_auth(self, request, connection):
        credentials = self.basic_credentials(request)
        if credentials is not None:
            connection.session.add_event("ICM authentication attempt", data={
                "method": "basic",
                "user": credentials[0],
                "password": credentials[1],
                "client": self.client(request),
                "path": request.path})
        title, status_text = LOGON_FAILED_TEXTS.get(self.logon_language(request),
                                                    LOGON_FAILED_TEXTS["EN"])
        body = (self.logon_failed_page
                .replace(b"{{TITLE}}", title.encode("utf-8"))
                .replace(b"{{STATUS_TEXT}}", status_text.encode("utf-8"))
                .replace(b"{{YEAR}}", str(datetime.now(timezone.utc).year).encode()))
        return self.response(request, 401, "Unauthorized", [
            self.usercontext_cookie(request),
            ("content-type", "text/html; charset=utf-8"),
            ("content-length", str(len(body))),
            ("sap-authenticated", "false"),
            ("sap-system", self.persona.sid),
            ("www-authenticate", 'Basic realm="SAP NetWeaver Application Server [%s/%s]"'
             % (self.persona.sid, self.client(request))),
            ("sap-server", "true"),
            ("sap-perf-fesrec", _perf_fesrec())], body)

    def icf_ping(self, request, connection):
        body = b"<html><body>Server reached.</body></html>"
        return self.response(request, 200, "OK", [
            self.usercontext_cookie(request),
            ("content-type", "text/html; charset=utf-8"),
            ("content-length", str(len(body))),
            ("sap-authenticated", "not required"),
            ("expires", "0"),
            ("sap-server", "true"),
            ("sap-perf-fesrec", _perf_fesrec())], body)

    def icf_info(self, request, connection):
        local_address = connection.server.server_address[0] if connection else None
        body = self.persona.rfc_system_info_xml(local_address).encode("utf-8")
        return self.response(request, 200, "OK", [
            self.usercontext_cookie(request),
            ("content-type", "text/xml"),
            ("content-length", str(len(body))),
            ("sap-authenticated", "not required"),
            ("sap-server", "true"),
            ("sap-perf-fesrec", _perf_fesrec())], body)

    def icf_icman_ping(self, request, connection):
        body = ("<HTML><HEAD><TITLE>SAP Web Application Server</TITLE></HEAD><BODY> "
                "---server on host <b> %s</b> system <b> %s (000) </b> successfully "
                "reached<br></BODY></HTML>" % (self.persona.hostname.ljust(33),
                                               self.persona.instance_name)).encode("utf-8")
        headers = [self.usercontext_cookie(request),
                   ("content-type", "text/html; charset=utf-8"),
                   ("content-length", str(len(body))),
                   ("sap-authenticated", "not required")]
        # The ICM answers this one itself and places the connection header
        # before its own headers
        if request.version >= "HTTP/1.1" and not request.keep_alive:
            headers.append(("connection", "close"))
        headers += [("sap-server", "true"), ("sap-perf-fesrec", _perf_fesrec())]
        return self.response(request, 200, "OK", headers, body)

    def icf_logoff(self, request, connection):
        expired = "0; expires=Tue, 01-Jan-1980 00:00:01 GMT; path=/"
        sid, client = self.persona.sid, self.client(request)
        headers = [("set-cookie", "sap-usercontext=%s" % expired),
                   ("set-cookie", "SAP_SESSIONID_%s_%s=%s" % (sid, client, expired)),
                   ("set-cookie", "sap-XSRF_%s_%s=%s" % (sid, client, expired)),
                   ("set-cookie", "SPNegoTokenRequested=%s" % expired),
                   ("set-cookie", "OIDCTokenRequested=%s" % expired),
                   ("content-type", "text/html; charset=utf-8"),
                   ("content-length", str(len(self.logoff_page))),
                   ("sap-authenticated", "not required"),
                   ("sap-server", "true"),
                   ("cache-control", "no-cache"),
                   ("pragma", "no-cache"),
                   ("expires", "0"),
                   ("sap-perf-fesrec", _perf_fesrec())]
        return self.response(request, 200, "OK", headers, self.logoff_page)

    def icf_icm_admin(self, request, connection):
        """The ICM administration pages redirect to their logon page."""
        location = "/sap/admin/public/session_logon.html"
        body = ("<HTML><HEAD><TITLE></TITLE></HEAD><BODY><H1>302 Resource has moved "
                "temporarily</H1><br>Requested resource can now be found here: "
                "<a href=\"%s\">%s</a> <br>\n</BODY></HTML>" % (location, location)).encode()
        return HTTPResponse(302, "Moved Temporarily", [
            ("date", formatdate(usegmt=True)),
            ("server", ""),
            ("pragma", "no-cache"),
            ("connection", "close"),
            ("location", location),
            ("content-type", "text/html")], body, version="HTTP/1.0", close=True)

    # Non-HTTP input

    def non_http_response(self, kind):
        """The ICM answers input that is not HTTP (including TLS on a plain
        port) with its generic 400 page over HTTP/1.0 and closes."""
        now = datetime.now(timezone.utc)
        body = (self.bad_request_page
                .replace(b"{{TAG}}", b"{%08x}" % getrandbits(32))
                .replace(b"{{SERVER_TIME}}", now.strftime("%Y-%m-%d %H:%M:%S").encode())
                .replace(b"{{YEAR}}", str(now.year).encode()))
        # The ICM pads the Content-Length value
        head = ("HTTP/1.0 400 Bad Request\r\n"
                "date: %s\r\n"
                "pragma: no-cache\r\n"
                "connection: close\r\n"
                "content-length: %-7d\r\n"
                "content-type: text/html\r\n\r\n" % (formatdate(usegmt=True), len(body)))
        return head.encode("ascii") + body
