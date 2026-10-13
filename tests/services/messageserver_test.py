# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import unittest
from unittest.mock import Mock

from scapy.packet import Raw
from pysap.SAPMS import SAPMS, SAPMSPayload, SAPMSPeerPayload

from honeysap.core.config import Configuration
from honeysap.core.http import HTTPRequest
from honeysap.services.messageserver.messageserver import (
    SAPMSServerHandler, SAPMSHTTPService)

class MessageServerHandlerTest(unittest.TestCase):

    def make_ms_http_service(self, **config):
        options = {"virtual": True, "hostname": "example.invalid"}
        options.update(config)
        return SAPMSHTTPService(Configuration(options), Mock(), Mock(), Mock())

    def make_request(self, path, headers=None, version="HTTP/1.1"):
        return HTTPRequest("GET", path, version, headers or [], b"", b"")

    def test_message_server_redirect_has_valid_headers_and_byte_length(self):
        service = self.make_ms_http_service()
        response = service.handle_request(self.make_request("/caf\xe9"), None)
        headers, body = response.to_bytes().split(b"\r\n\r\n", 1)
        self.assertTrue(headers.startswith(b"HTTP/1.1 307 TEMPORARY REDIRECT"))
        self.assertIn(b"location: http://example.invalid:8000/caf\xe9", headers)
        self.assertIn(("Content-Length: %d" % len(body)).encode(), headers)
        self.assertTrue(response.close)

    def test_message_server_redirect_escapes_url_in_html(self):
        service = self.make_ms_http_service()
        response = service.handle_request(self.make_request("/?next=<script>"), None)
        self.assertNotIn(b"<script>", response.body)
        self.assertIn(b"&lt;script&gt;", response.body)

    def test_message_server_redirect_can_use_request_host(self):
        service = self.make_ms_http_service(redirect_hostname="request")
        request = self.make_request("/", [("Host", "honeysap.example:8100")])
        response = service.handle_request(request, None)
        self.assertIn(("location", "http://honeysap.example:8000/"), response.headers)

    def test_message_server_paths_are_case_sensitive(self):
        service = self.make_ms_http_service()
        response = service.handle_request(self.make_request("/MSGSERVER/TEXT/LOGON"), None)
        self.assertEqual(response.status, 307)

    def test_text_logon(self):
        service = self.make_ms_http_service(
            hostname="vhcala4hci", system={"sid": "A4H"},
            services=[{"service": "SAPICMService", "listener_port": 50000},
                      {"service": "SAPICMService", "listener_port": 50001,
                       "tls": {"enabled": True}}])
        request = self.make_request("/msgserver/text/logon?version=1.2",
                                    [("Host", "x:1")])
        response = service.handle_request(request, None)
        self.assertEqual(response.body,
                         b"version 1.2\nvhcala4hci_A4H_00\n"
                         b"DIAG\tvhcala4hci\t3200\tLB=7\nRFC\tvhcala4hci\t3300\t\n"
                         b"HTTP\tvhcala4hci\t50000\t\nHTTPS\tvhcala4hci\t50001\t\n"
                         b"HTTP\tvhcala4hci\t50000\tVHOST=0\nHTTPS\tvhcala4hci\t50001\tVHOST=0\n\n")
        self.assertEqual([name for name, _ in response.headers],
                         ["Content-Type", "Content-Length", "location", "host", "date",
                          "server", "connection"])
        self.assertIn(("host", "x:1"), response.headers)
        self.assertIn(("server", "SAP Message Server, release 916 (A4H)"), response.headers)

    def test_group_without_query_is_a_kernel_error(self):
        service = self.make_ms_http_service()
        response = service.handle_request(self.make_request("/msgserver/text/group"), None)
        self.assertEqual((response.status, response.version), (400, "HTTP/1.0"))
        self.assertIn(b"required field ~query_string not found", response.body)
        response = service.handle_request(self.make_request("/msgserver/text/group?SPACE&NOPE"),
                                          None)
        self.assertIn(b"detailed informations for logon group SPACE", response.body)
        self.assertIn(b"specified group not found", response.body)

    def test_message_server_endpoint_returns_a_response(self):
        service = self.make_ms_http_service()
        request = self.make_request("/msgserver")
        response = service.handle_request(request, None)
        self.assertEqual(response.status, 200)
        self.assertIn(b"List of commands", response.body)
        self.assertEqual(service.request_details(request), {"action": "msgserver"})

    def test_message_server_rejects_non_ms_payload(self):
        handler = SAPMSServerHandler.__new__(SAPMSServerHandler)
        handler.packet = Raw(b"not SAPMS")
        handler.request = Mock()
        handler.session = Mock()
        handler.client_address = ("127.0.0.1", 1)
        handler.handle_data()
        handler.session.add_event.assert_called_once()
        self.assertIsInstance(handler.request.send.call_args.args[0], SAPMS)

    def test_message_server_records_opcode_from_structured_payload(self):
        handler = SAPMSServerHandler.__new__(SAPMSServerHandler)
        handler.packet = SAPMS(flag=2, iflag=1) / SAPMSPayload(opcode=5)
        handler.request = Mock()
        handler.session = Mock()
        handler.client_address = ("127.0.0.1", 1)

        handler.handle_data()

        event = handler.session.add_event.call_args.kwargs["data"]
        self.assertEqual(event["opcode"], 5)
        self.assertEqual(event["opcode_name"], "MS_SERVER_LST")

    def test_message_server_records_opcode_from_peer_payload(self):
        handler = SAPMSServerHandler.__new__(SAPMSServerHandler)
        handler.packet = (SAPMS(flag=2, iflag=0, toname="listener") /
                          SAPMSPeerPayload(opcode=1, message=b"hello"))
        handler.request = Mock()
        handler.session = Mock()
        handler.client_address = ("127.0.0.1", 1)

        handler.handle_data()

        event = handler.session.add_event.call_args.kwargs["data"]
        self.assertEqual(event["opcode"], 1)
        self.assertEqual(event["opcode_name"], "MS_SERVER_CHG")


class MessageServerParameterTest(unittest.TestCase):

    def setUp(self):
        self.service = SAPMSHTTPService(Configuration({
            "virtual": True, "listener_port": 8101,
            "system": {"sid": "A4H", "hostname": "vhcala4hci", "client": "001"},
            "profile_parameters": {"login/min_password_lng": 6, "gw/acl_mode": None,
                                   "z/custom": "on"}}), Mock(), Mock(), Mock())

    def get(self, target):
        return self.service.handle_request(
            HTTPRequest("GET", target, "HTTP/1.1", [("Host", "x:8101")], b"", b""), None)

    def test_text(self):
        response = self.get("/msgserver/text/parameter?SAPSYSTEMNAME&&rdisp/myname"
                            "&ms/server_port_0&login/min_password_lng&gw/acl_mode&z/custom"
                            "&login%2fmin_password_lng&")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body,
                         b"SAPSYSTEMNAME = A4H\nrdisp/myname = vhcala4hci_A4H_01\n"
                         b"ms/server_port_0 = PROT=HTTP,PORT=8101,TIMEOUT=20,PROCTIMEOUT=60\n"
                         b"login/min_password_lng = 6\ngw/acl_mode = not found\n"
                         b"z/custom = on\nlogin%2fmin_password_lng = not found\n")
        self.assertEqual(dict(response.headers)["Content-Type"], "text/plain; charset=utf-8")

    def test_html_and_xml_escape_names(self):
        html = self.get("/msgserver/html/parameter?<s>&a\"b&DIR_TRANS").body
        self.assertIn(b"<TR><TD>&lt;s&gt;</TD><TD>not found</TD></TR>\r\n"
                      b"<TR><TD>a&#x22;b</TD><TD>not found</TD></TR>\r\n"
                      b"<TR><TD>DIR_TRANS</TD><TD>/usr/sap/trans</TD></TR>\r\n", html)
        xml = self.get("/msgserver/xml/parameter?gw/sec_info").body
        self.assertIn(b"<item>\r\n<NAME>gw&#x2f;sec_info</NAME>\r\n"
                      b"<VALUE>/usr/sap/A4H/SYS/global/secinfo</VALUE>\r\n</item>\r\n", xml)

    def test_missing_query_and_case(self):
        response = self.get("/msgserver/text/parameter")
        self.assertEqual((response.status, response.version), (400, "HTTP/1.0"))
        self.assertEqual(self.get("/msgserver/TEXT/PARAMETER?SAPSYSTEMNAME").status, 307)

    def test_event_lists_parameters(self):
        request = HTTPRequest("GET", "/msgserver/text/parameter?gw/acl_mode&snc/enable",
                              "HTTP/1.1", [], b"", b"")
        self.assertEqual(self.service.request_details(request),
                         {"action": "parameter_query",
                          "parameters": ["gw/acl_mode", "snc/enable"]})

    def test_system_uuid_is_stable(self):
        value = self.get("/msgserver/text/parameter?system/uuid").body
        self.assertEqual(value, self.get("/msgserver/text/parameter?system/uuid").body)
        self.assertEqual(value.decode().split(" = ")[1][14], "4")
