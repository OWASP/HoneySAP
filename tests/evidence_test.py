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

# Standard imports
import json
import socket
import unittest
from base64 import b64decode
from struct import pack
from unittest.mock import Mock, patch
# External imports
from pysap.SAPDiag import SAPDiag, SAPDiagDP
from pysap.SAPMS import SAPMS
from pysap.SAPNI import SAPNIStreamSocket
# Custom imports
from honeysap.core.config import Configuration
from honeysap.core.event import Event
from honeysap.core.evidence import LoggingPolicy, WireTap, install_tap
from honeysap.core.session import Session, SessionManager
from honeysap.services.dispatcher.dispatcher import SAPDispatcherService
from honeysap.services.gateway.gateway import SAPGatewayService
from honeysap.services.messageserver.messageserver import SAPMSService
from honeysap.services.saprouter.saprouter import (
    SAPRouterService, SAPRouterServerHandler)


def ni_frame(payload):
    return pack("!I", len(payload)) + payload


GENERIC_PAYLOAD = b"\x00\x01HONEYSAP-EVIDENCE\xff"
# The MS stream decodes every frame as SAPMS, so it needs a valid header
MS_PAYLOAD = bytes(SAPMS(fromname="HONEYSAP"))


class LoggingPolicyTest(unittest.TestCase):

    def test_defaults(self):
        policy = LoggingPolicy.from_config(Configuration())
        self.assertTrue(policy.raw_payloads)
        self.assertTrue(policy.response_events)
        self.assertTrue(policy.unparsed_input)
        self.assertEqual(policy.max_payload_bytes, 65536)
        self.assertEqual(policy.connection_events, "close")

    def test_invalid_options_are_rejected(self):
        for options in ({"raw_payloads": "yes"}, {"max_payload_bytes": -1},
                        {"connection_events": "sometimes"}, {"bogus": True}):
            with self.assertRaises(ValueError):
                LoggingPolicy(**options)

    def test_connection_events_false_means_none(self):
        self.assertEqual(LoggingPolicy(connection_events=False).connection_events,
                         "none")

    def test_payload_truncation_and_suppression(self):
        policy = LoggingPolicy(max_payload_bytes=4)
        self.assertEqual(policy.payload(b"abcdef"), (b"abcd", 6, True))
        self.assertEqual(policy.payload(b"abc"), (b"abc", 3, False))
        self.assertEqual(policy.payload("text"), ("text", None, False))
        self.assertEqual(LoggingPolicy(raw_payloads=False).payload(b"abc"),
                         (None, 3, False))
        self.assertEqual(LoggingPolicy(max_payload_bytes=0).payload(b"x" * 100000)[2],
                         False)

    def test_service_logging_overrides_global_per_option(self):
        config = Configuration({"logging": {"max_payload_bytes": 10,
                                            "connection_events": "all"},
                                "services": [{"service": "S",
                                              "logging": {"connection_events": "none"}}]})
        service_config = config.config_for("services", "service", "S")[0]
        policy = LoggingPolicy.from_config(service_config)
        self.assertEqual(policy.max_payload_bytes, 10)
        self.assertEqual(policy.connection_events, "none")


class SessionPolicyTest(unittest.TestCase):

    def make_session(self, **options):
        events = []
        session = Session(None, "test", "127.0.0.1", 1, "127.0.0.1", 2,
                          enqueue=events.append)
        session.logging_policy = LoggingPolicy(**options)
        return session, events

    def test_truncated_payload_is_flagged(self):
        session, events = self.make_session(max_payload_bytes=2)
        session.add_event("x", data={"a": 1}, request=b"abcd", response=b"z")
        event = events[0]
        self.assertEqual(event.request, b"ab")
        self.assertEqual(event.response, b"z")
        self.assertEqual(event.data, {"a": 1, "request_size": 4,
                                      "request_truncated": True,
                                      "response_size": 1})

    def test_disabled_raw_payloads_keep_size_only(self):
        session, events = self.make_session(raw_payloads=False)
        session.add_event("x", request=b"abcd")
        self.assertIsNone(events[0].request)
        self.assertEqual(events[0].data, {"request_size": 4})

    def test_event_carries_connection_id(self):
        session, events = self.make_session()
        session.connection_id = "conn-1"
        session.add_event("x")
        serialized = json.loads(repr(events[0]))
        self.assertEqual(serialized["schema_version"], Event.schema_version)
        self.assertEqual(serialized["connection_id"], "conn-1")


class WireTapTest(unittest.TestCase):

    def test_records_both_directions(self):
        left, right = socket.socketpair()
        try:
            tap = WireTap(left)
            right.sendall(b"ping")
            self.assertEqual(tap.recv(10), b"ping")
            tap.sendall(b"pong")
            self.assertEqual(right.recv(10), b"pong")
            self.assertEqual((tap.take_rx(), tap.take_tx()), (b"ping", b"pong"))
            self.assertEqual((tap.bytes_in, tap.bytes_out), (4, 4))
            self.assertEqual(tap.take_rx(), b"")
        finally:
            left.close()
            right.close()

    def test_nested_taps_share_connection_and_split_counters(self):
        left, right = socket.socketpair()
        try:
            router_stream = SAPNIStreamSocket(left)
            router_tap = install_tap(router_stream)
            right.sendall(b"route")
            router_tap.recv(5)
            # A routed service wraps the router's socket in its own stream
            routed_stream = SAPNIStreamSocket(router_stream.ins)
            routed_tap = install_tap(routed_stream)
            right.sendall(b"data")
            routed_tap.recv(4)
            self.assertEqual(routed_tap.connection_id, router_tap.connection_id)
            self.assertEqual(routed_tap.bytes_in, 4)
            self.assertEqual(router_tap.bytes_in, 9)
        finally:
            left.close()
            right.close()


class ServiceEvidenceTest(unittest.TestCase):
    """Send known bytes to each NI service and check the logged evidence."""

    services = [
        (SAPDispatcherService, {}, GENERIC_PAYLOAD),
        (SAPGatewayService, {}, GENERIC_PAYLOAD),
        (SAPMSService, {}, MS_PAYLOAD),
        (SAPRouterService, {"release": 720}, GENERIC_PAYLOAD),
    ]

    def run_service(self, service_cls, wire, extra=None, logging=None):
        config = {"enabled": True, "virtual": True,
                  "listener_address": "127.0.0.1", "listener_port": 1}
        config.update(extra or {})
        if logging:
            config["logging"] = logging
        manager = SessionManager(Configuration())
        service = service_cls(Configuration(config), Mock(), manager, Mock())
        client, server_side = socket.socketpair()
        client.settimeout(5)
        server_side.settimeout(5)
        try:
            client.sendall(wire)
            client.shutdown(socket.SHUT_WR)
            stream = SAPNIStreamSocket(server_side,
                                       keep_alive=service.server.keep_alive,
                                       base_cls=service.server.base_cls)
            service.handle_virtual(stream, ("192.0.2.1", 40000))
        finally:
            client.close()
            server_side.close()
        events = []
        while not manager.event_queue.empty():
            events.append(manager.event_queue.get())
        return events

    def events_named(self, events, name):
        return [event for event in events if event.event == name]

    def test_received_packet_logs_exact_wire_bytes(self):
        for service_cls, extra, payload in self.services:
            wire = ni_frame(payload)
            with self.subTest(service=service_cls.__name__):
                events = self.run_service(service_cls, wire, extra)
                received = self.events_named(events, "Received packet")
                self.assertEqual(len(received), 1)
                logged = json.loads(repr(received[0]))
                self.assertEqual(b64decode(logged["request"]), wire)
                self.assertEqual(logged["data"]["request_size"], len(wire))
                self.assertTrue(logged["connection_id"])
                connection_id = received[0].session.connection_id
                self.assertTrue(all(event.session.connection_id == connection_id
                                    for event in events))

    def test_connection_closed_summarizes_connection(self):
        for service_cls, extra, payload in self.services:
            wire = ni_frame(payload)
            with self.subTest(service=service_cls.__name__):
                events = self.run_service(service_cls, wire, extra)
                closed = self.events_named(events, "Connection closed")
                self.assertEqual(len(closed), 1)
                self.assertIs(events[-1], closed[0])
                self.assertEqual(closed[0].data["bytes_in"], len(wire))
                self.assertEqual(closed[0].data["packets_in"], 1)
                self.assertIn(closed[0].data["close_reason"],
                              ("client_close", "server_close", "error"))

    def test_connect_without_data_produces_events(self):
        for service_cls, extra, _ in self.services:
            with self.subTest(service=service_cls.__name__):
                events = self.run_service(service_cls, b"", extra,
                                          logging={"connection_events": "all"})
                self.assertEqual([event.event for event in events],
                                 ["Connection opened", "Connection closed"])
                self.assertEqual(events[1].data["bytes_in"], 0)
                self.assertEqual(events[1].data["close_reason"], "client_close")

    def test_connection_events_can_be_disabled(self):
        events = self.run_service(SAPMSService, b"",
                                  logging={"connection_events": "none"})
        self.assertEqual(events, [])

    def test_truncated_frame_is_reported_as_unparsed(self):
        wire = pack("!I", 100) + b"partial"
        for service_cls, extra, _ in self.services:
            with self.subTest(service=service_cls.__name__):
                events = self.run_service(service_cls, wire, extra)
                unparsed = self.events_named(events, "Unparsed input")
                self.assertEqual(len(unparsed), 1)
                self.assertEqual(unparsed[0].request, wire)
                self.assertEqual(unparsed[0].data["stage"], "recv")

    def test_oversized_frame_is_reported_as_unparsed(self):
        wire = pack("!I", 0x7fffffff) + b"junk"
        events = self.run_service(SAPGatewayService, wire)
        unparsed = self.events_named(events, "Unparsed input")
        self.assertEqual(len(unparsed), 1)
        self.assertEqual(unparsed[0].data["stage"], "decode")
        self.assertIn("error", unparsed[0].data)
        self.assertEqual(unparsed[0].request, wire[:4])

    def test_gateway_short_payload_is_reported_as_unparsed(self):
        wire = ni_frame(b"\x02")
        events = self.run_service(SAPGatewayService, wire)
        unparsed = self.events_named(events, "Unparsed input")
        self.assertEqual(len(unparsed), 1)
        self.assertEqual(unparsed[0].data["stage"], "short_payload")
        self.assertEqual(unparsed[0].request, wire)

    def test_undecodable_packet_is_reported_as_unparsed(self):
        # Too short for the SAPMS header: decoding fails inside the NI stream
        wire = ni_frame(b"\x00\x01abc")
        events = self.run_service(SAPMSService, wire)
        self.assertEqual([event.event for event in events],
                         ["Unparsed input", "Connection closed"])
        self.assertEqual(events[0].data["stage"], "decode")
        self.assertEqual(events[0].request, wire)
        self.assertEqual(events[1].data["close_reason"], "error")

    def test_handler_exception_is_reported_as_unparsed(self):
        wire = ni_frame(MS_PAYLOAD)

        def broken(handler):
            raise ValueError("boom")
        with patch.object(SAPMSService.handler_cls, "handle_data", broken):
            events = self.run_service(SAPMSService, wire)
        unparsed = self.events_named(events, "Unparsed input")
        self.assertEqual(len(unparsed), 1)
        self.assertEqual(unparsed[0].data["stage"], "handle_data")
        self.assertEqual(unparsed[0].data["error"], "ValueError: boom")
        self.assertEqual(unparsed[0].request, wire)
        closed = self.events_named(events, "Connection closed")
        self.assertEqual(closed[0].data["close_reason"], "error")

    def test_sent_bytes_are_logged(self):
        # The gateway answers a CHECK_GATEWAY style request
        events = self.run_service(SAPGatewayService, ni_frame(GENERIC_PAYLOAD))
        sent = self.events_named(events, "Sent packet")
        self.assertEqual(len(sent), 1)
        self.assertTrue(sent[0].response)
        self.assertEqual(sent[0].data["response_size"], len(sent[0].response))
        closed = self.events_named(events, "Connection closed")
        self.assertEqual(closed[0].data["bytes_out"], len(sent[0].response))

    def test_response_events_can_be_disabled(self):
        events = self.run_service(SAPGatewayService, ni_frame(GENERIC_PAYLOAD),
                                  logging={"response_events": False})
        self.assertEqual(self.events_named(events, "Sent packet"), [])

    def test_payload_cap_applies_to_service_events(self):
        wire = ni_frame(GENERIC_PAYLOAD + b"A" * 200)
        events = self.run_service(SAPRouterService, wire, {"release": 720},
                                  logging={"max_payload_bytes": 16})
        received = self.events_named(events, "Received packet")[0]
        self.assertEqual(received.request, wire[:16])
        self.assertTrue(received.data["request_truncated"])
        self.assertEqual(received.data["request_size"], len(wire))

    def test_default_logs_only_connection_closed(self):
        events = self.run_service(SAPMSService, b"")
        self.assertEqual([event.event for event in events], ["Connection closed"])

    def test_unparsed_input_can_be_disabled(self):
        wire = pack("!I", 100) + b"partial"
        events = self.run_service(SAPGatewayService, wire,
                                  logging={"unparsed_input": False})
        self.assertEqual(self.events_named(events, "Unparsed input"), [])
        self.assertEqual(self.events_named(events, "Connection closed")[0].data["bytes_in"],
                         len(wire))

    def test_raw_payloads_can_be_disabled(self):
        wire = ni_frame(GENERIC_PAYLOAD)
        events = self.run_service(SAPGatewayService, wire,
                                  logging={"raw_payloads": False})
        received = self.events_named(events, "Received packet")[0]
        self.assertIsNone(received.request)
        self.assertEqual(received.data["request_size"], len(wire))
        sent = self.events_named(events, "Sent packet")[0]
        self.assertIsNone(sent.response)
        self.assertEqual(json.loads(repr(received))["request"], "")

    def test_invalid_logging_configuration_stops_the_service(self):
        with self.assertRaises(ValueError):
            self.run_service(SAPMSService, b"", logging={"max_payload_bytes": "lots"})

    def test_socket_timeout_reports_partial_frame(self):
        manager = SessionManager(Configuration())
        service = SAPGatewayService(Configuration({"enabled": True, "virtual": True,
                                                   "listener_address": "127.0.0.1",
                                                   "listener_port": 1}),
                                    Mock(), manager, Mock())
        client, server_side = socket.socketpair()
        try:
            wire = pack("!I", 100) + b"partial"
            client.sendall(wire)
            # The client stays connected: the read times out
            server_side.settimeout(0.2)
            stream = SAPNIStreamSocket(server_side, base_cls=service.server.base_cls)
            service.handle_virtual(stream, ("192.0.2.1", 40000))
        finally:
            client.close()
            server_side.close()
        events = []
        while not manager.event_queue.empty():
            events.append(manager.event_queue.get())
        unparsed = self.events_named(events, "Unparsed input")
        self.assertEqual(unparsed[0].request, wire)
        self.assertEqual(unparsed[0].data["stage"], "recv")
        self.assertEqual(self.events_named(events, "Connection closed")[0]
                         .data["close_reason"], "timeout")

    def test_saprouter_timeout_close_reason(self):
        def timeout(handler):
            raise handler._timeout
        with patch.object(SAPRouterServerHandler, "receive_packet", timeout):
            events = self.run_service(SAPRouterService, b"", {"release": 720})
        self.assertEqual(self.events_named(events, "Connection closed")[0]
                         .data["close_reason"], "timeout")

    def test_saprouter_routed_connection_keeps_its_close_reason(self):
        def route(handler):
            handler.server.clients[handler.client_address].routed = True
            return True

        def routed(handler):
            raise ConnectionResetError("target closed")
        with patch.object(SAPRouterServerHandler, "receive_packet", route), \
                patch.object(SAPRouterServerHandler, "handle_data", lambda handler: None), \
                patch.object(SAPRouterServerHandler, "handle_routed", routed):
            events = self.run_service(SAPRouterService, b"", {"release": 720})
        self.assertEqual(self.events_named(events, "Connection closed")[0]
                         .data["close_reason"], "routed")

    def test_dispatcher_events_carry_wire_bytes(self):
        wire = ni_frame(bytes(SAPDiagDP() / SAPDiag()))
        events = self.run_service(SAPDispatcherService, wire)
        init = self.events_named(events, "Initialization request received")[0]
        self.assertEqual(init.request, wire)
        self.assertIsInstance(init.response, bytes)
        sent = self.events_named(events, "Sent packet")[0]
        # The login screen as sent, with its NI length header
        self.assertEqual(sent.response[4:], init.response)
        self.assertEqual(sent.response[:4], pack("!I", len(init.response)))


class ProfileTest(unittest.TestCase):

    def test_packaged_profiles_have_valid_logging_options(self):
        for profile in ("profiles/internal.yml", "profiles/external.yml"):
            with self.subTest(profile=profile):
                config = Configuration()
                config.update(profile, from_file=True)
                self.assertIn("logging", config)
                for service in config.services:
                    for service_config in config.config_for("services", "service",
                                                            service["service"]):
                        LoggingPolicy.from_config(service_config)


def test_suite():
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for case in (LoggingPolicyTest, SessionPolicyTest, WireTapTest,
                 ServiceEvidenceTest, ProfileTest):
        suite.addTest(loader.loadTestsFromTestCase(case))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
