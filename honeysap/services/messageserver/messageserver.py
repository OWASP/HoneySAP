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
from email.utils import formatdate
from html import escape
from socket import timeout
from urllib.parse import urlsplit
# External imports
from pysap.SAPMS import (SAPMS, SAPMSPayload, SAPMSPeerPayload,
                         ms_flag_values, ms_iflag_values,
                         ms_opcode_values)
from pysap.SAPNI import SAPNIServerThreaded, SAPNIServerHandler, SAPNIClient
# Custom imports
from honeysap.core.logger import Loggeable
from honeysap.core.evidence import EvidenceHandlerMixin
from honeysap.core.http import HTTPResponse
from honeysap.core.service import BaseHTTPService, BaseTCPService


class SAPMSClient(SAPNIClient):
    pass


class SAPMSServerHandler(Loggeable, EvidenceHandlerMixin, SAPNIServerHandler):

    def __init__(self, request, client_address, server):
        Loggeable.__init__(self)
        self.config = server.config
        client_ip, client_port = client_address
        server_ip, server_port = server.server_address
        self.session = server.session_manager.get_session("message_server",
                                                          client_ip,
                                                          client_port,
                                                          server_ip,
                                                          server_port)
        SAPNIServerHandler.__init__(self, request, client_address, server)

    def handle_data(self):
        try:
            if SAPMS not in self.packet:
                self.session.add_event("Invalid packet received",
                                       data={"client": str(self.client_address)})
                self.logger.debug("Invalid packet sent to SAPMS")
                self.request.send(SAPMS())
                return

            ms = self.packet[SAPMS]
            flag = getattr(ms, "flag", None)
            iflag = getattr(ms, "iflag", None)
            body = ms.payload
            if isinstance(body, (SAPMSPayload, SAPMSPeerPayload)):
                opcode = body.opcode
            else:
                opcode = None
            fromname = getattr(ms, "fromname", "").strip()
            toname = getattr(ms, "toname", "").strip()

            data = {
                "client": str(self.client_address),
                "flag": flag,
                "flag_name": ms_flag_values.get(flag, "UNKNOWN"),
                "iflag": iflag,
                "iflag_name": ms_iflag_values.get(iflag, "UNKNOWN"),
                "fromname": fromname,
                "toname": toname,
            }
            if opcode is not None:
                data["opcode"] = opcode
                data["opcode_name"] = ms_opcode_values.get(opcode, "UNKNOWN")

            self.session.add_event("MS packet received",
                                   data=data,
                                   request=self.raw_request)

        except timeout:
            self.logger.debug("Timeout connection from %s", self.client_address)


class SAPMSServerThreaded(SAPNIServerThreaded):
    def __init__(self, server_address, RequestHandlerClass,
                 bind_and_activate=True, base_cls=SAPMS, **kwargs):
        SAPNIServerThreaded.__init__(self, server_address, RequestHandlerClass,
                                     bind_and_activate=bind_and_activate,
                                     base_cls=base_cls, **kwargs)


class SAPMSService(BaseTCPService):

    server_cls = SAPMSServerThreaded
    handler_cls = SAPMSServerHandler

    default_port = 3600


class SAPMSHTTPService(BaseHTTPService):

    default_port = 8100
    default_release = 720
    default_instance = "PRD"
    default_hostname = "sapnw702"
    session_service_name = "message_server_http"
    request_event_name = "MS HTTP request"

    def version_string(self):
        """Build the server version header using the release and instance name"""
        release = self.config.get("release", self.default_release)
        instance = self.config.get("instance", self.default_instance)

        return "SAP Message Server, release %d (%s)" % (int(release), instance)

    def request_details(self, request):
        if request.path.startswith("/msgserver"):
            return {"action": "msgserver"}
        return {"action": "redirect_to_icm"}

    def handle_request(self, request, connection):
        if request.path.startswith("/msgserver"):
            self.logger.debug("Received request to msgserver endpoint")
            return self.msgserver_response(request)
        self.logger.debug("Redirecting to ICM service")
        return self.build_301_to_icm(request)

    def msgserver_response(self, request):
        return HTTPResponse(404, "Not Found", [("Content-Length", "0")], b"",
                            version=request.version)

    def build_301_to_icm(self, request):
        """Build a redirection to the ICM service"""
        hostname = self._redirect_hostname(request)
        try:
            icm_configs = self.config.config_for("services", "service", "SAPICMService")
            icm_port = icm_configs[0].get("listener_port", 8000)
        except (IndexError, AttributeError):
            icm_port = 8000
        url = "http://%s:%d%s" % (hostname, icm_port, request.target)

        body = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML><HEAD>
<TITLE>301 MOVED PERMANENTLY</TITLE>
</HEAD><BODY>
<H1>Moved Permanently</H1>
The document has moved <A HREF="%s"> here</A>
</BODY></HTML>
""" % (escape(url, quote=True))

        body_bytes = body.encode("utf-8")
        headers = [("Content-Type", "text/html; charset=utf-8"),
                   ("Content-Length", str(len(body_bytes))),
                   ("location", url),
                   ("date", formatdate(usegmt=True)),
                   ("server", self.version_string())]
        if request.version >= "HTTP/1.1":
            headers.append(("connection", "close"))
        return HTTPResponse(301, "MOVED PERMANENTLY", headers, body_bytes,
                            version=request.version, close=True)

    def _redirect_hostname(self, request):
        """Return the configured ICM redirect hostname.

        ``redirect_hostname: request`` preserves the authority the client used
        for the Message Server HTTP request, making a container deployment
        reachable without requiring a fictitious SAP hostname in client DNS.
        """
        configured = self.config.get(
            "redirect_hostname",
            self.config.get("hostname", self.default_hostname))
        if configured != "request":
            return configured

        try:
            hostname = urlsplit("//%s" % request.header("Host", "")).hostname
        except ValueError:
            hostname = None
        if not hostname:
            return self.config.get("hostname", self.default_hostname)
        if ":" in hostname:
            return "[%s]" % hostname
        return hostname
