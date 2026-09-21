# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from scapy.packet import Raw
from pysap.SAPMS import SAPMS, SAPMSPayload, SAPMSPeerPayload

from honeysap.core.config import Configuration
from honeysap.services.messageserver.messageserver import (
    SAPMSServerHandler, SAPMSHTTPServerHandler)

class MessageServerHandlerTest(unittest.TestCase):

    def make_ms_http_handler(self, path):
        handler = SAPMSHTTPServerHandler.__new__(SAPMSHTTPServerHandler)
        handler.server = SimpleNamespace(config=Configuration({"hostname": "example.invalid"}))
        handler.path = path
        handler.request_version = "HTTP/1.1"
        handler.protocol_version = "HTTP/1.1"
        handler.wfile = io.BytesIO()
        handler.client_address = ("127.0.0.1", 1)
        handler.headers = {}
        handler.command = "GET"
        handler.session = Mock()
        return handler

    def test_message_server_redirect_has_valid_headers_and_byte_length(self):
        handler = self.make_ms_http_handler("/café")
        handler.build_301_to_icm()
        headers, body = handler.wfile.getvalue().split(b"\r\n\r\n", 1)
        self.assertTrue(headers.startswith(b"HTTP/1.1 301"))
        self.assertIn(b"location: http://example.invalid:8000/caf\xe9", headers)
        self.assertIn(("Content-Length: %d" % len(body)).encode(), headers)

    def test_message_server_redirect_escapes_url_in_html(self):
        handler = self.make_ms_http_handler("/?next=<script>")
        handler.build_301_to_icm()
        _, body = handler.wfile.getvalue().split(b"\r\n\r\n", 1)
        self.assertNotIn(b"<script>", body)
        self.assertIn(b"&lt;script&gt;", body)

    def test_message_server_redirect_can_use_request_host(self):
        handler = self.make_ms_http_handler("/")
        handler.server.config.redirect_hostname = "request"
        handler.headers = {"Host": "honeysap.example:8100"}

        handler.build_301_to_icm()

        headers, _ = handler.wfile.getvalue().split(b"\r\n\r\n", 1)
        self.assertIn(b"location: http://honeysap.example:8000/", headers)

    def test_message_server_endpoint_returns_a_response(self):
        handler = self.make_ms_http_handler("/msgserver")
        handler.do_request()
        self.assertTrue(handler.wfile.getvalue().startswith(b"HTTP/1.1 404"))
        handler.session.add_event.assert_called_once()

    def test_message_server_closes_overlong_request_line(self):
        handler = self.make_ms_http_handler("/")
        handler.rfile = io.BytesIO(b"G" * 65537 + b"\r\n")
        handler.close_connection = 0
        handler.handle_one_request()
        self.assertEqual(handler.close_connection, 1)

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
