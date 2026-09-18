# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import socket
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from gevent.event import Event as GreenletEvent
from scapy.packet import Raw

from honeysap.core.config import Configuration
from honeysap.services.forwarder import ForwarderService

class ForwarderServiceTest(unittest.TestCase):



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
