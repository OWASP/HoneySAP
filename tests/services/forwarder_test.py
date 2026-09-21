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
from honeysap.core.session import SessionManager
from honeysap.services.forwarder import ForwarderService

class ForwarderServiceTest(unittest.TestCase):



    def make_forwarder(self):
        service = ForwarderService.__new__(ForwarderService)
        service.config = Configuration({"target_address": "example.invalid",
                                        "target_port": 1234})
        return service

    def test_forwarded_payload_remains_bytes_in_event_and_send(self):
        service = self.make_forwarder()
        local = Mock()
        remote = Mock(spec=["sendall"])
        local.recv.return_value = b"\x00\xffpayload"
        session = Mock()
        service.recv_send(local, remote, session, request=True)
        remote.sendall.assert_called_once_with(b"\x00\xffpayload")
        event = session.add_event.call_args.args[0]
        self.assertEqual(event.request, b"\x00\xffpayload")
        self.assertIsNone(event.response)

        local.recv.return_value = Raw(b"scapy payload")
        service.recv_send(local, remote, session, request=False)
        self.assertEqual(remote.sendall.call_args.args[0], b"scapy payload")
        event = session.add_event.call_args.args[0]
        self.assertEqual(event.response, b"scapy payload")

    def test_empty_payload_signals_closed_socket(self):
        service = self.make_forwarder()
        local = Mock()
        session = Mock()
        local.recv.return_value = b""
        with self.assertRaises(socket.error):
            service.recv_send(local, Mock(), session, request=False)
        session.add_event.assert_not_called()

    def test_failed_outbound_connect_closes_socket(self):
        service = self.make_forwarder()
        service.session_manager = Mock()
        outbound = Mock()
        outbound.connect.side_effect = socket.error("unreachable")
        with patch("honeysap.services.forwarder.socket.socket", return_value=outbound):
            with self.assertRaises(socket.error):
                service.create_remote(("127.0.0.1", 1), "example.invalid", 1234)
        outbound.close.assert_called_once_with()

    def test_remote_session_carries_route_lineage(self):
        service = self.make_forwarder()
        service.session_manager = SessionManager(Configuration())
        outbound = Mock()
        context = {"campaign_uuid": "campaign-1",
                   "parent_session_uuid": "router-session-1"}
        with patch("honeysap.services.forwarder.socket.socket", return_value=outbound):
            __, session = service.create_remote(("127.0.0.1", 1),
                                                "example.invalid", 1234,
                                                context)
        self.assertEqual(session.campaign_uuid, "campaign-1")
        self.assertEqual(session.parent_session_uuid, "router-session-1")

    def test_connection_sides_close_after_forwarding(self):
        service = self.make_forwarder()
        service.stopped = GreenletEvent()
        client = Mock()
        remote = Mock()
        session = Mock()
        service.create_remote = Mock(return_value=(remote, session))
        service.handle = Mock(side_effect=lambda *args: service.stopped.set())
        service.connections = set()
        service._handle_client(client, ("127.0.0.1", 1), release_slot=False)
        client.close.assert_called_once_with()
        remote.close.assert_called_once_with()
