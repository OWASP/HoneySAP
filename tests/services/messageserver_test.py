# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import unittest
from types import SimpleNamespace
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
        self.assertTrue(headers.startswith(b"HTTP/1.1 301"))
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

    def test_message_server_endpoint_returns_a_response(self):
        service = self.make_ms_http_service()
        request = self.make_request("/msgserver")
        response = service.handle_request(request, None)
        self.assertEqual(response.status, 404)
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
