# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import unittest
from base64 import b64encode
from unittest.mock import Mock

from honeysap.core.config import Configuration
from honeysap.core.http import HTTPRequest
from honeysap.services.icm.icm import SAPICMService


SYSTEM = {"sid": "A4H", "hostname": "vhcala4hci", "client": "001",
          "release": "816", "kernel_release": "916", "ip_address": "192.0.2.9"}


class ICMServiceTest(unittest.TestCase):

    def setUp(self):
        self.service = SAPICMService(Configuration({"virtual": True, "system": SYSTEM}),
                                     Mock(), Mock(), Mock())
        self.connection = Mock()
        self.connection.server.server_address = ("0.0.0.0", 8000)

    def get(self, path, headers=None, method="GET", version="HTTP/1.1"):
        request = HTTPRequest(method, path, version, headers or [("Host", "x")], b"", b"")
        return self.service.handle_request(request, self.connection)

    def header_names(self, response):
        return [name for name, _ in response.headers]

    def test_icf_resolution_is_case_insensitive_and_by_segment(self):
        self.assertEqual(self.service.resolve("/SAP/PUBLIC/PING")[0], "ping")
        self.assertEqual(self.service.resolve("/sap/public/ping/xyz")[0], "ping")
        self.assertEqual(self.service.resolve("/sap/public/pingx")[0], "not_found")
        self.assertEqual(self.service.resolve("/sap/bc/soap/rfc")[0], "auth")

    def test_not_found_page(self):
        response = self.get("/nonexistent")
        self.assertEqual((response.status, response.reason), (404, "Not found"))
        self.assertEqual(self.header_names(response),
                         ["content-type", "content-length", "sap-server",
                          "sap-authenticated", "sap-perf-fesrec"])
        self.assertEqual(len(response.body), 9240)
        self.assertIn(b" 404 Not found ", response.body)

    def test_ping(self):
        response = self.get("/sap/public/ping")
        self.assertEqual(response.body, b"<html><body>Server reached.</body></html>")
        self.assertEqual(response.headers[0],
                         ("set-cookie", "sap-usercontext=sap-client=001; path=/"))
        self.assertIn(("expires", "0"), response.headers)

    def test_info_reports_persona(self):
        response = self.get("/sap/public/info")
        self.assertIn(("content-type", "text/xml"), response.headers)
        self.assertIn(b"<RFCHOST>vhcala4h</RFCHOST><RFCSYSID>A4H</RFCSYSID>", response.body)
        self.assertIn(b"<RFCMACH>  390</RFCMACH>", response.body)
        self.assertIn(b"<RFCTZONE>     0</RFCTZONE>", response.body)
        self.assertIn(b"<RFCIPADDR>192.0.2.9</RFCIPADDR><RFCKERNRL>916</RFCKERNRL>", response.body)

    def test_icman_ping(self):
        response = self.get("/sap/public/icman/ping")
        self.assertEqual(len(response.body), 205)
        self.assertIn(b"system <b> vhcala4hci_A4H_00 (000) </b>", response.body)

    def test_auth_required_logs_basic_credentials(self):
        authorization = "Basic " + b64encode(b"DDIC:19920706").decode()
        response = self.get("/sap/bc/soap/rfc?sap-client=000",
                            [("Authorization", authorization)])
        self.assertEqual(response.status, 401)
        self.assertIn(("www-authenticate",
                       'Basic realm="SAP NetWeaver Application Server [A4H/000]"'),
                      response.headers)
        event = self.connection.session.add_event.call_args
        self.assertEqual(event.args[0], "ICM authentication attempt")
        self.assertEqual(event.kwargs["data"]["user"], "DDIC")
        self.assertEqual(event.kwargs["data"]["password"], "19920706")

    def test_logon_failed_page_language(self):
        english = self.get("/sap/opu/odata/", [("Accept-Language", "en-US")])
        german = self.get("/sap/opu/odata/?sap-language=de")
        self.assertIn(b"401 Not authorized", english.body)
        self.assertIn(b"401 Nicht autorisiert", german.body)
        self.assertEqual(len(german.body), 9321)
        self.assertEqual(german.headers[0],
                         ("set-cookie", "sap-usercontext=sap-language=DE&sap-client=001; path=/"))

    def test_head_has_no_body_and_close_is_echoed(self):
        response = self.get("/sap/public/ping", [("Connection", "close")], method="HEAD")
        self.assertEqual(response.body, b"")
        self.assertIn(("content-length", "41"), response.headers)
        self.assertEqual(response.headers[-1], ("connection", "close"))

    def test_http10_answer(self):
        response = self.get("/sap/public/ping", [], version="HTTP/1.0")
        self.assertEqual(response.version, "HTTP/1.0")
        self.assertTrue(response.close)
        self.assertNotIn("connection", self.header_names(response))

    def test_icm_admin_redirect(self):
        response = self.get("/sap/admin/public/default.html")
        self.assertEqual(response.to_bytes().split(b"\r\n")[0],
                         b"HTTP/1.0 302 Moved Temporarily")
        self.assertIn(("location", "/sap/admin/public/session_logon.html"), response.headers)

    def test_icf_configuration(self):
        service = SAPICMService(Configuration({"virtual": True,
                                               "icf": {"/sap/bc/soap/rfc": "inactive"}}),
                                Mock(), Mock(), Mock())
        self.assertEqual(service.resolve("/sap/bc/soap/rfc")[0], "inactive")
        self.assertEqual(service.resolve("/sap/bc/soap/wsdl")[0], "auth")
        with self.assertRaises(ValueError):
            SAPICMService(Configuration({"virtual": True, "icf": {"/x": "bogus"}}),
                          Mock(), Mock(), Mock())
