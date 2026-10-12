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
from datetime import datetime, timezone
from email.utils import formatdate
from random import getrandbits
# External imports
from flask.templating import render_template
# Custom imports
from honeysap.core.service import BaseHTTPService


TEMPLATES = os.path.join(os.path.dirname(__file__), "templates")


class SAPICMService(BaseHTTPService):

    default_port = 8000
    default_release = 720
    template_folder = TEMPLATES
    session_service_name = "icm_http"
    request_event_name = "ICM HTTP request"

    def setup_server(self):
        with open(os.path.join(TEMPLATES, "icm_bad_request.html"), "rb") as f:
            self.bad_request_page = f.read()
        super(SAPICMService, self).setup_server()

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

    def version_string(self):
        release = str(self.config.get("release", self.default_release))
        release = "%s.%s" % (release[0], release[1:])
        icm_release = self.config.get("icm_release", release)

        return "SAP NetWeaver Application Server %s / ICM %s" % (release,
                                                                 icm_release)

    def route_index(self):
        return render_template("404.html"), 404
    route_index.rule = "/"

    def error_400(self, code):
        return render_template("400.html"), 400

    def error_404(self, code):
        return render_template("404.html"), 404
