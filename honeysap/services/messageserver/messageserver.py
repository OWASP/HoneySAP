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


MS_COMMANDS = [
    ("/msgserver/commands", "list of commands"),
    ("/msgserver/html/aslist", "list of application server (HTML)"),
    ("/msgserver/xml/aslist", "list of application server (XML)"),
    ("/msgserver/text/aslist", "list of application server (TEXT)"),
    ("/msgserver/text/aslist?version=1.1", "list of application server (hashed server name) (TEXT)"),
    ("/msgserver/html/lglist", "list of logon groups (HTML)"),
    ("/msgserver/xml/lglist", "list of logon groups (XML)"),
    ("/msgserver/text/lglist", "list of logon groups (TEXT)"),
    ("/msgserver/html/logon", "logon data (HTML)"),
    ("/msgserver/xml/logon", "logon data (XML)"),
    ("/msgserver/text/logon", "logon data (TEXT)"),
    ("/msgserver/text/logon?version=1.1", "logon data (hashed server name) (TEXT)"),
    ("/msgserver/text/logon?version=1.2", "logon data (hashed server name with virtual hosts) (TEXT)"),
    ("/msgserver/text/logon?version=1.3",
     "logon data (hashed server name with virtual hosts and TCP socket info) (TEXT)"),
]

# Empty logon data fields of the XML logon list, after https
MS_XML_EMPTY_FIELDS = (
    ["ftp", "smtp", "nntp"] +
    ["diag_ext", "diags_ext", "rfc_ext", "rfcs_ext", "http_ext", "https_ext",
     "ftp_ext", "smtp_ext", "nntp_ext"] +
    ["j2ee", "j2ees", "j2ee_ext", "j2ees_ext", "p4", "p4s", "iiop", "iiops", "sdm",
     "telnet", "debug", "debugproxy", "p4http", "httpri", "httspri", "j2eeri",
     "j2eesri", "trxns"])

HTML_HEAD = ('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\r\n<HTML><HEAD>\r\n'
             '<TITLE>%s</TITLE>\r\n</HEAD><BODY>\r\n')


class SAPMSHTTPService(BaseHTTPService):
    """Message Server HTTP port (81NN): the /msgserver commands answered
    like the Message Server, everything else redirected to the ICM."""

    default_port = 8100
    session_service_name = "message_server_http"
    request_event_name = "MS HTTP request"

    # Service name of the dispatcher port in /etc/services (3200 is
    # registered as tick-port)
    default_service_names = {3200: "tick-port"}

    def setup_server(self):
        super(SAPMSHTTPService, self).setup_server()
        persona = self.persona
        instance = int(persona.instance_number)
        self.diag_port = self._service_port("SAPDispatcherService", 3200 + instance)
        self.rfc_port = self._service_port("SAPGatewayService", 3300 + instance)
        self.http_port = self._service_port("SAPICMService", 8000 + instance, tls=False)
        self.https_port = self._service_port("SAPICMService", None, tls=True)
        self.dispatcher_service = self.config.get(
            "dispatcher_service_name",
            self.default_service_names.get(self.diag_port, "sapdp%02d" % instance))
        self.logon_groups = self.config.get("logon_groups", ["PUBLIC", "SPACE"])

    def _service_port(self, service_name, default, tls=None):
        for service in self.config.get("services") or []:
            if service.get("service") != service_name or not service.get("enabled", True):
                continue
            uses_tls = bool((service.get("tls") or {}).get("enabled"))
            if tls is None or uses_tls == tls:
                return service.get("listener_port", default)
        return default

    def version_string(self):
        """Server header: release is the kernel release"""
        release = self.config.get("release", self.persona.kernel_release)
        instance = self.config.get("instance", self.persona.sid)
        return "SAP Message Server, release %s (%s)" % (release, instance)

    @property
    def server_address_text(self):
        return self.persona.address(self.listener_address)

    # Request handling

    def request_details(self, request):
        if request.path.startswith("/msgserver"):
            return {"action": "msgserver"}
        return {"action": "redirect_to_icm"}

    def handle_request(self, request, connection):
        handler = self.commands().get(request.path)
        if handler is None:
            self.logger.debug("Redirecting to ICM service")
            return self.redirect_to_icm(request)
        return handler(request)

    def commands(self):
        return {"/msgserver": self.command_list,
                "/msgserver/": self.command_list,
                "/msgserver/commands": self.command_list,
                "/msgserver/html/aslist": self.html_aslist,
                "/msgserver/xml/aslist": self.xml_aslist,
                "/msgserver/text/aslist": self.text_aslist,
                "/msgserver/html/lglist": self.html_lglist,
                "/msgserver/xml/lglist": self.xml_lglist,
                "/msgserver/text/lglist": self.text_lglist,
                "/msgserver/html/logon": self.html_logon,
                "/msgserver/xml/logon": self.xml_logon,
                "/msgserver/text/logon": self.text_logon,
                "/msgserver/html/group": self.html_group,
                "/msgserver/text/group": self.text_group}

    def response(self, request, body, content_type="text/plain; charset=utf-8",
                 status=200, reason="OK", location=None):
        """Responses of the Message Server, headers in its order and case.
        The Host header of the request is echoed back."""
        body = body.encode("utf-8") if isinstance(body, str) else body
        headers = [("Content-Type", content_type),
                   ("Content-Length", str(len(body))),
                   ("location", location or self.persona.hostname)]
        http11 = request.version >= "HTTP/1.1"
        if http11 and request.header("Host") is not None:
            headers.append(("host", request.header("Host")))
        headers += [("date", formatdate(usegmt=True)),
                    ("server", self.version_string())]
        if http11:
            headers.append(("connection", "close"))
        # The Message Server sends the body also for HEAD
        return HTTPResponse(status, reason, headers, body,
                            version="HTTP/1.1" if http11 else "HTTP/1.0", close=True)

    def bad_request(self, request, message):
        body = (HTML_HEAD % "400 BAD REQUEST" +
                "<H1>400 BAD REQUEST</H1>\r\n<p>The following error occured:\r\n"
                "<p>%s\r\n<p>%s\r\n</BODY></HTML>\r\n" % (message, self.version_string()))
        return HTTPResponse(400, "BAD REQUEST",
                            [("Date", formatdate(usegmt=True)),
                             ("content-type", "text/html")],
                            body.encode("utf-8"), version="HTTP/1.0", close=True)

    def redirect_to_icm(self, request):
        """Unknown paths are redirected to the ICM HTTP port"""
        url = "http://%s:%s%s" % (self._redirect_hostname(request), self.http_port,
                                  request.target)
        body = (HTML_HEAD % "307 TEMPORARY REDIRECT" +
                "<H1>Moved Temporary</H1>\r\nThe document has moved "
                "<A HREF=\"%s\"> here</A>\r\n</BODY></HTML>\r\n" % escape(url, quote=True))
        return self.response(request, body, "text/html; charset=utf-8", 307,
                             "TEMPORARY REDIRECT", location=url)

    def _redirect_hostname(self, request):
        """Return the configured ICM redirect hostname.

        ``redirect_hostname: request`` preserves the authority the client used
        for the Message Server HTTP request, making a container deployment
        reachable without requiring a fictitious SAP hostname in client DNS.
        """
        configured = self.config.get("redirect_hostname", self.persona.hostname)
        if configured != "request":
            return configured

        try:
            hostname = urlsplit("//%s" % request.header("Host", "")).hostname
        except ValueError:
            hostname = None
        if not hostname:
            return self.persona.hostname
        if ":" in hostname:
            return "[%s]" % hostname
        return hostname

    # Commands

    def command_list(self, request):
        base = "http://%s:%s" % (self.persona.hostname, self.listener_port)
        rows = "".join('<TR><TD> <A HREF="%s%s">%s</A> </TD><TD> %s </TD></TR>\r\n'
                       % (base, path, path, description)
                       for path, description in MS_COMMANDS)
        rows += ("<TR><TD> /msgserver/html/group?group[&group[&group...]] </TD>"
                 "<TD> logon group info (HTML) </TD></TR>\r\n"
                 "<TR><TD> /msgserver/text/group?group[&group[&group...]] </TD>"
                 "<TD> logon group info (TEXT) </TD></TR>\r\n")
        body = (HTML_HEAD % "List of commands" +
                "<H1>List of commands</H1>\r\n<BR>\r\n<TABLE BORDER>\r\n"
                "<TR><TH>URL</TH><TH>Description</TH></TR>\r\n" + rows +
                "</TABLE>\r\n<BR>\r\n<BR>\r\n<DIV>%s</DIV>\r\n</BODY></HTML>\r\n"
                % self.version_string())
        return self.response(request, body, "text/html; charset=utf-8")

    def _server_row(self):
        persona = self.persona
        return (persona.instance_name, persona.hostname, self.dispatcher_service,
                self.server_address_text, str(self.diag_port), "DIA UPD BTC SPO UP2 ICM ")

    def html_aslist(self, request):
        body = (HTML_HEAD % "List of application server" +
                "<H1>List of application server</H1>\r\n<TABLE BORDER>\r\n"
                "<TR><TH>Name</TH><TH>Hostname</TH><TH>Service</TH><TH>IP adress</TH>"
                "<TH>Port</TH><TH>Types</TH></TR>\r\n<TR>" +
                "".join("<TD>%s</TD>" % value for value in self._server_row()) +
                "</TR>\r\n</TABLE>\r\n</BODY></HTML>\r\n")
        return self.response(request, body, "text/html; charset=utf-8")

    def _xml_server(self):
        name, host, service, address, port, types = self._server_row()
        return ("<item>\r\n<MSXXLIST>\r\n<NAME>%s</NAME>\r\n<HOST>%s</HOST>\r\n"
                "<SERVICES>%s</SERVICES>\r\n<MSGTYPES>187</MSGTYPES>\r\n"
                "<HOSTADR>%s</HOSTADR>\r\n<SERVNO>%s</SERVNO>\r\n</MSXXLIST>\r\n"
                "<msgnames>%s</msgnames>\r\n" % (name, host, service, address, port, types))

    def xml_aslist(self, request):
        body = ('<?xml version="1.0" encoding="UTF-8"?>\r\n<APPLICATION_SERVER>\r\n'
                "<DESCRIPTION>list of application server</DESCRIPTION>\r\n"
                "<VERSION>1.0</VERSION>\r\n<SERVER_LIST>\r\n" + self._xml_server() +
                "</item>\r\n</SERVER_LIST>\r\n</APPLICATION_SERVER>\r\n")
        return self.response(request, body, "text/html; charset=utf-8")

    def text_aslist(self, request):
        version = "1.1" if self._version(request) not in (None, "1.0") else "1.0"
        body = "version %s\n%s\n" % (version, "\t".join(self._server_row()))
        return self.response(request, body)

    def _groups(self):
        address = self.server_address_text
        return [(group, address, str(self.diag_port), self.persona.release)
                for group in self.logon_groups]

    def html_lglist(self, request):
        body = (HTML_HEAD % "List of logon groups" +
                "<H1>List of logon groups</H1>\r\n<TABLE BORDER>\r\n"
                "<TR><TH>Name</TH><TH>IP adress</TH><TH>port</TH><TH>release</TH></TR>\r\n" +
                "".join("<TR>%s</TR>\r\n" % "".join("<TD>%s</TD>" % value for value in group)
                        for group in self._groups()) +
                "</TABLE>\r\n</BODY></HTML>\r\n")
        return self.response(request, body, "text/html; charset=utf-8")

    def xml_lglist(self, request):
        body = ('<?xml version="1.0" encoding="UTF-8"?>\r\n<FAVOURITE_LOGON>\r\n'
                "<DESCRIPTION>list of logon groups</DESCRIPTION>\r\n"
                "<VERSION>1.0</VERSION>\r\n<LOGON_LIST>\r\n" +
                "".join("<item>\r\n<NAME>%s</NAME>\r\n<IPADR>%s</IPADR>\r\n"
                        "<PORT>%s</PORT>\r\n<RELEASE>%s</RELEASE>\r\n</item>\r\n" % group
                        for group in self._groups()) +
                "</LOGON_LIST>\r\n</FAVOURITE_LOGON>\r\n")
        return self.response(request, body, "text/html; charset=utf-8")

    def text_lglist(self, request):
        body = "version 1.0\n" + "".join("\t".join(group) + "\n" for group in self._groups())
        return self.response(request, body)

    def _logon_entries(self):
        host = self.persona.hostname
        entries = [("DIAG", host, self.diag_port, "LB=7"), ("RFC", host, self.rfc_port, "")]
        if self.http_port:
            entries.append(("HTTP", host, self.http_port, ""))
        if self.https_port:
            entries.append(("HTTPS", host, self.https_port, ""))
        return entries

    def html_logon(self, request):
        rows = "".join("<TR><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD></TR>\r\n"
                       % (kind, host, port, data or "&nbsp")
                       for kind, host, port, data in self._logon_entries())
        body = (HTML_HEAD % "Logon data of application server" +
                "<H1>Logon data of application server</H1>\r\n<BR><TABLE BORDER>\r\n"
                "<TR><TH COLSPAN=4>%s</TH></TR>\r\n"
                "<TR><TH>Logon</TH><TH>Host</TH><TH>Port</TH><TH>Data</TH></TR>\r\n"
                % self.persona.instance_name + rows + "</TABLE>\r\n</BODY></HTML>\r\n")
        return self.response(request, body, "text/html; charset=utf-8")

    def xml_logon(self, request):
        ports = {kind.lower(): (host, port) for kind, host, port, _ in self._logon_entries()}
        fields = ""
        for kind in ("diag", "diags", "rfc", "rfcs", "http", "https"):
            host, port = ports.get(kind, ("", ""))
            fields += "<%s_host>%s</%s_host>\r\n<%s_port>%s</%s_port>\r\n" % (
                kind, host, kind, kind, port, kind)
        for kind in MS_XML_EMPTY_FIELDS:
            base, _, ext = kind.partition("_")
            suffix = "_ext" if ext else ""
            fields += "<%s_host%s></%s_host%s>\r\n<%s_port%s></%s_port%s>\r\n" % (
                base, suffix, base, suffix, base, suffix, base, suffix)
        body = ('<?xml version="1.0" encoding="UTF-8"?>\r\n<APPLICATION_SERVER>\r\n'
                "<DESCRIPTION>logon data of application server</DESCRIPTION>\r\n"
                "<VERSION>1.0</VERSION>\r\n<SERVER_LIST>\r\n" + self._xml_server() +
                fields + "</item>\r\n</SERVER_LIST>\r\n</APPLICATION_SERVER>\r\n")
        return self.response(request, body, "text/html; charset=utf-8")

    def _version(self, request):
        for name, _, value in (part.partition("=") for part in request.query.split("&")):
            if name == "version":
                return value
        return None

    def text_logon(self, request):
        version = self._version(request) or "1.0"
        if version not in ("1.0", "1.1", "1.2", "1.3"):
            # What the Message Server answers to versions it does not know
            version = "1.809"
        lines = ["version %s" % version, self.persona.instance_name]
        entries = self._logon_entries()
        lines += ["%s\t%s\t%s\t%s" % entry for entry in entries]
        if version not in ("1.0", "1.1"):
            lines += ["%s\t%s\t%s\tVHOST=0" % (kind, host, port)
                      for kind, host, port, _ in entries if kind in ("HTTP", "HTTPS")]
        return self.response(request, "\n".join(lines) + "\n\n")

    def _group_text(self, request):
        text = ""
        for group in request.query.split("&"):
            if group in self.logon_groups:
                address = self.server_address_text
                text += ("detailed informations for logon group %s (with SNC)\n"
                         " ip adress = %s\n port = %s\n release = %s\n"
                         " application server name = %s\n"
                         " application server hostname = %s\n sncname = \n"
                         " extended load balance inactive\n\n"
                         % (group, address, self.diag_port, self.persona.release,
                            self.persona.instance_name, address))
            else:
                text += ("<pre>Message Server on host %s\nspecified group not found</pre>\n"
                         % self.persona.hostname)
        return text

    def _missing_query(self):
        return ("MsHttpGenHeader: required field ~query_string not found "
                "(/bas/%s_REL/src/krn/ms/msxxhttp.c [9052])" % self.persona.kernel_release)

    def html_group(self, request):
        if not request.query:
            return self.bad_request(request, self._missing_query())
        body = (HTML_HEAD % "Logon group informations" +
                "<H1>Logon group informations</H1>\r\n<PRE>\r\n<BR>\r\n" +
                self._group_text(request) + "</PRE>\r\n</BODY></HTML>\r\n")
        return self.response(request, body)

    def text_group(self, request):
        if not request.query:
            return self.bad_request(request, self._missing_query())
        return self.response(request, self._group_text(request))
