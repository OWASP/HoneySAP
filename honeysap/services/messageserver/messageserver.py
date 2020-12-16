# ===========
# HoneySAP - SAP low-interaction honeypot
#
# SECUREAUTH LABS. Copyright (C) 2019 SecureAuth Corporation. All rights reserved.
#
# The library was designed and developed by Martin Gallo from
# the SecureAuth's Innovation Labs team.
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
# ==============

# Standard imports
from socket import timeout
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
# External imports
from pysap import SAPMS
from pysap.SAPNI import SAPNIServerThreaded, SAPNIServerHandler, SAPNIClient
# Custom imports
from honeysap.core.logger import Loggeable
from honeysap.core.service import BaseTCPService


class SAPMSClient(SAPNIClient):
    pass


class SAPMSServerHandler(Loggeable, SAPNIServerHandler):

    def __init__(self, request, client_address, server):
        Loggeable.__init__(self)
        SAPNIServerHandler.__init__(self, request, client_address, server)

    def handle_data(self):
        self.packet.show()
        try:
            if SAPMS not in self.packet:
                self.logger.debug("Invalid packet sent to SAPMS")
                self.request.send(SAPMS())
        except timeout:
            self.logger.debug("Timeout connection from %s", self.client_address)


class SAPMSServerThreaded(SAPNIServerThreaded):
    pass


class SAPMSService(BaseTCPService):

    server_cls = SAPMSServerThreaded
    handler_cls = SAPMSServerHandler

    default_port = 3300


class SAPMSHTTPServerHandler(Loggeable, BaseHTTPRequestHandler):

    default_release = 720
    default_instance = "PRD"
    default_hostname = "sapnw702"

    def __init__(self, request, client_address, server):
        Loggeable.__init__(self)
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def log_message(self, fmt, *args):
        """Override log method to use our logging"""
        self.logger.debug(fmt, *args)

    def parse_request(self):
        """Override standard parsing to handle versions and not throw an error
        and instead close the connection"""
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = 1
        requestline = self.raw_requestline
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 3:
            command, path, version = words
            if version[:5] != 'HTTP/':
                self.close_connection = 1
                return False
            try:
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.close_connection = 1
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = 0
            if version_number > (1, 9):
                self.close_connection = 1
                return False
        elif not words:
            return False
        else:
            self.close_connection = 1
            return False
        self.command, self.path, self.request_version = command, path, version

        # Examine the headers and look for a Connection directive
        self.headers = self.MessageClass(self.rfile, 0)

        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = 0
        return True

    def handle_one_request(self):
        """Override standard handling to serve content on any HTTP verb"""
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                return
            self.do_request()
            self.wfile.flush()
        except timeout as e:
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
            return

    def version_string(self):
        """Build the server version header using the release and instance name"""
        release = self.server.config.get("release", self.default_release)
        instance = self.server.config.get("instance", self.default_instance)

        return "SAP Message Server, release %d (%s)" % (release,
                                                        instance)

    def build_301_to_icm(self):
        """Build a redirection to the ICM service"""
        hostname = self.server.config.get("hostname", self.default_hostname)
        icm_port = self.server.config.config_for("SAPICMService")[0].get("listener_port", 8000)
        url = "http://%s:%d%s" % (hostname,
                                  icm_port,
                                  self.path)

        try:
            may_version, min_version = map(int, self.request_version.split("/", 2)[1].split(".", 2))
        except:
            may_version, min_version = 1, 1

        http_version = "HTTP/%d.%d" % (may_version, min_version)

        body = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML><HEAD>
<TITLE>301 MOVED PERMANENTLY</TITLE>
</HEAD><BODY>
<H1>Moved Permanently</H1>
The document has moved <A HREF="%s"> here</A>
</BODY></HTML>
""" % (url)

        self.wfile.write("%s 301 MOVED PERMANENTLY\n" % http_version)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("location", url)
        self.send_header("date", self.date_time_string())
        self.send_header("server", self.version_string())
        if min_version >= 1:
            self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_request(self):
        if self.path.startswith("/msgserver"):
            self.logger.debug("Received request to msgserver endpoint")
            self.do_request_msgserver()
        else:
            self.logger.debug("Redirecting to ICM service")
            self.build_301_to_icm()

    def do_request_msgserver(self):
        pass


class SAPMSHTTPServerThreaded(ThreadingMixIn, HTTPServer):
    pass


class SAPMSHTTPService(BaseTCPService):

    server_cls = SAPMSHTTPServerThreaded
    handler_cls = SAPMSHTTPServerHandler

    default_port = 8100
