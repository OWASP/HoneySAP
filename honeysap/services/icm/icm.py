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
# External imports
from flask.templating import render_template
# Custom imports
from honeysap.core.service import BaseHTTPService


class SAPICMService(BaseHTTPService):

    default_port = 8000
    default_release = 720
    template_folder = "honeysap/services/icm/templates"

    def version_string(self):
        release = str(self.server.config.get("release", self.default_release))
        release = "%s.%s" % (release[0], release[1:])
        icm_release = self.server.config.get("icm_release", release)

        return "SAP NetWeaver Application Server %s / ICM %s" % (release,
                                                                 icm_release)

    def route_index(self):
        pass
    route_index.rule = "/"

    def error_400(self, code):
        error = "-21"
        version = "7200"
        date_time = "Tue Aug 19 20:21:02 2014"
        server = "sapnw702_NSP_00"
        base_url = "http://sapnw702:8000"
        hostname = "sapnw702"
        return render_template("400.html"), 400

    def error_404(self, code):
        return render_template("404.html"), 404
