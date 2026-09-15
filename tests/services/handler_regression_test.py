# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import io
import socket
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from gevent.event import Event as GreenletEvent
from scapy.packet import Raw
from pysap.SAPMS import SAPMS
from pysap.SAPRFC import SAPRFC

from honeysap.core.config import Configuration
from honeysap.services.forwarder import ForwarderService
from honeysap.services.dispatcher.dispatcher import SAPDispatcherServerHandler
from honeysap.services.gateway.gateway import SAPGatewayServerHandler
from honeysap.services.icm.icm import SAPICMService
from honeysap.services.messageserver.messageserver import (
    SAPMSServerHandler, SAPMSHTTPServerHandler)
from honeysap.services.saprouter.saprouter import SAPRouterServerHandler


class HTTPHandlerRegressionTest(unittest.TestCase):

    def test_icm_version_and_index_without_tcp_listener(self):
        service = SAPICMService(Configuration({"virtual": True,
                                               "release": 720,
                                               "icm_release": "7.20"}),
                                Mock(), Mock(), Mock())
        self.assertIn("7.20", service.version_string())
        response = service.app.test_client().get("/")
        self.assertEqual(response.status_code, 404)

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


class NIHandlerRegressionTest(unittest.TestCase):

    def test_message_server_rejects_non_ms_payload(self):
        handler = SAPMSServerHandler.__new__(SAPMSServerHandler)
        handler.packet = Raw(b"not SAPMS")
        handler.request = Mock()
        handler.session = Mock()
        handler.client_address = ("127.0.0.1", 1)
        handler.handle_data()
        handler.session.add_event.assert_called_once()
        self.assertIsInstance(handler.request.send.call_args.args[0], SAPMS)

    def test_gateway_short_payload_and_monitor_stop_do_not_raise(self):
        handler = SAPGatewayServerHandler.__new__(SAPGatewayServerHandler)
        handler.packet = SimpleNamespace(payload=Raw(b"\x06"))
        handler.session = Mock()
        handler.client_address = ("127.0.0.1", 1)
        handler.handle_data()
        handler.session.add_event.assert_called_once()
        handler._handle_gateway(b"\x03\x05", 3)
        self.assertEqual(handler.session.add_event.call_args.args[0],
                         "Dangerous gateway command attempted")

    def test_gateway_check_uses_rfc_packet(self):
        handler = SAPGatewayServerHandler.__new__(SAPGatewayServerHandler)
        handler.client_address = ("127.0.0.1", 1)
        handler.request = Mock()
        handler.session = Mock()
        handler._handle_gateway(b"\x03\x01", 3)
        self.assertIsInstance(handler.request.send.call_args.args[0], SAPRFC)

    def test_router_rejects_non_router_packet_without_indexing_it(self):
        handler = SAPRouterServerHandler.__new__(SAPRouterServerHandler)
        handler.packet = Raw(b"invalid")
        handler.session = Mock()
        handler.handle_data()
        self.assertEqual(handler.session.add_event.call_args.args[0],
                         "Invalid SAPRouter packet")

    def test_dispatcher_client_termination_closes_connection(self):
        handler = SAPDispatcherServerHandler.__new__(SAPDispatcherServerHandler)
        handler.client_address = ("127.0.0.1", 1)
        handler.server = SimpleNamespace(clients={handler.client_address: object()})
        handler.session = Mock()
        handler.request = Mock()
        diag = SimpleNamespace(com_flag_TERM_EOC=True, com_flag_TERM_EOP=False)
        handler.packet = MagicMock()
        handler.packet.__getitem__.return_value = diag
        handler.handle_msg()
        handler.request.close.assert_called_once_with()
        self.assertNotIn(handler.client_address, handler.server.clients)

    def test_dispatcher_malformed_initialized_packet_logs_off(self):
        handler = SAPDispatcherServerHandler.__new__(SAPDispatcherServerHandler)
        handler.client_address = ("127.0.0.1", 1)
        handler.server = SimpleNamespace(clients={handler.client_address: object()})
        handler.packet = Raw(b"invalid")
        handler.session = Mock()
        handler.request = Mock()
        handler.handle_msg()
        self.assertNotIn(handler.client_address, handler.server.clients)
        self.assertEqual(handler.session.add_event.call_args_list[0].args[0],
                         "Invalid dispatcher packet")


class ForwarderRegressionTest(unittest.TestCase):

    def make_forwarder(self):
        service = ForwarderService.__new__(ForwarderService)
        service.config = Configuration({"target_address": "example.invalid",
                                        "target_port": 1234})
        service.session = Mock()
        return service

    def test_forwarded_payload_remains_bytes_in_event_and_send(self):
        service = self.make_forwarder()
        local = Mock()
        remote = Mock(spec=["sendall"])
        local.recv.return_value = b"\x00\xffpayload"
        service.recv_send(local, remote, request=True)
        remote.sendall.assert_called_once_with(b"\x00\xffpayload")
        event = service.session.add_event.call_args.args[0]
        self.assertEqual(event.request, b"\x00\xffpayload")
        self.assertIsNone(event.response)

        local.recv.return_value = Raw(b"scapy payload")
        service.recv_send(local, remote, request=False)
        self.assertEqual(remote.sendall.call_args.args[0], b"scapy payload")
        event = service.session.add_event.call_args.args[0]
        self.assertEqual(event.response, b"scapy payload")

    def test_empty_payload_signals_closed_socket(self):
        service = self.make_forwarder()
        local = Mock()
        local.recv.return_value = b""
        with self.assertRaises(socket.error):
            service.recv_send(local, Mock(), request=False)
        service.session.add_event.assert_not_called()

    def test_failed_outbound_connect_closes_socket(self):
        service = self.make_forwarder()
        service.session_manager = Mock()
        outbound = Mock()
        outbound.connect.side_effect = socket.error("unreachable")
        with patch("honeysap.services.forwarder.socket.socket", return_value=outbound):
            with self.assertRaises(socket.error):
                service.create_remote(("127.0.0.1", 1), "example.invalid", 1234)
        outbound.close.assert_called_once_with()

    def test_connection_sides_close_after_forwarding(self):
        service = self.make_forwarder()
        service.stopped = GreenletEvent()
        client = Mock()
        remote = Mock()
        service.listener = SimpleNamespace(ins=Mock())
        service.listener.ins.accept.return_value = (client, ("127.0.0.1", 1))
        service.create_remote = Mock(return_value=remote)
        service.handle = Mock(side_effect=lambda *args: service.stopped.set())
        service.run()
        client.close.assert_called_once_with()
        remote.close.assert_called_once_with()
