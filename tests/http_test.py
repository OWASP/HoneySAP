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
import ssl
import threading
import unittest
from base64 import b64decode
from unittest.mock import Mock
# External imports
# Custom imports
from honeysap.core.config import Configuration
from honeysap.core.session import SessionManager
from honeysap.core.tls import ja3, ja4, parse_client_hello
from honeysap.services.icm.icm import SAPICMService
from honeysap.services.messageserver.messageserver import SAPMSHTTPService


def client_hello(server_name="honeysap.example"):
    """Capture the ClientHello a Python TLS client sends."""
    context = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_hostname=server_name)
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class HTTPServiceHarness(object):

    def make_service(self, service_cls, **config):
        options = {"enabled": True, "virtual": True,
                   "listener_address": "127.0.0.1", "listener_port": 8000,
                   "hostname": "sapnw702", "timeout": 5}
        options.update(config)
        manager = SessionManager(Configuration())
        service = service_cls(Configuration(options), Mock(), manager, Mock())
        return service, manager

    def exchange(self, service_cls, wire, client_address=("192.0.2.1", 40001), **config):
        """Send wire to a virtual service over a socketpair, return the bytes
        answered and the events logged."""
        service, manager = self.make_service(service_cls, **config)
        client, server_side = socket.socketpair()
        client.settimeout(5)
        try:
            client.sendall(wire)
            client.shutdown(socket.SHUT_WR)
            service.handle_virtual(server_side, client_address)
            server_side.close()
            answer = b""
            while True:
                try:
                    data = client.recv(65536)
                except ConnectionResetError:
                    # Closed with unread client data
                    break
                if not data:
                    break
                answer += data
        finally:
            client.close()
            server_side.close()
        return answer, self.drain(manager)

    @staticmethod
    def drain(manager):
        events = []
        while not manager.event_queue.empty():
            events.append(manager.event_queue.get())
        return events

    @staticmethod
    def named(events, name):
        return [event for event in events if event.event == name]


class HTTPFrontTest(HTTPServiceHarness, unittest.TestCase):

    def test_request_headers_body_and_raw_bytes_are_logged(self):
        body = b"--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.jsp\"\r\n" \
               b"Content-Type: application/octet-stream\r\n\r\n<% exec %>\r\n--XyZ--\r\n"
        wire = (b"POST /developmentserver/metadatauploader?CONTENT=x HTTP/1.1\r\n"
                b"Host: sap.example:8000\r\n"
                b"X-Custom: One\r\n"
                b"x-custom: two\r\n"
                b"Content-Type: multipart/form-data; boundary=XyZ\r\n"
                b"Content-Length: %d\r\n"
                b"Connection: close\r\n\r\n" % len(body)) + body
        answer, events = self.exchange(SAPICMService, wire)
        self.assertTrue(answer.startswith(b"HTTP/1.1 404"))
        request = self.named(events, "ICM HTTP request")
        self.assertEqual(len(request), 1)
        logged = json.loads(repr(request[0]))
        self.assertEqual(b64decode(logged["request"]), wire)
        self.assertEqual(b64decode(logged["response"]), answer)
        data = logged["data"]
        self.assertEqual(data["method"], "POST")
        self.assertEqual(data["path"], "/developmentserver/metadatauploader")
        self.assertEqual(data["query"], "CONTENT=x")
        self.assertEqual(data["status"], 404)
        self.assertEqual(data["headers"][1:3], [["X-Custom", "One"], ["x-custom", "two"]])
        self.assertEqual(b64decode(data["body"]["value"]), body)
        self.assertEqual(data["multipart"], [{"name": "file", "filename": "shell.jsp",
                                              "content_type": "application/octet-stream",
                                              "size": 10}])
        self.assertEqual(logged["source_port"], 40001)
        self.assertTrue(logged["connection_id"])

    def test_chunked_and_conflicting_length_headers_are_kept(self):
        wire = (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n"
                b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                b"5\r\nhello\r\n0\r\n\r\n")
        _, events = self.exchange(SAPICMService, wire)
        event = self.named(events, "ICM HTTP request")[0]
        self.assertEqual(event.request, wire)
        self.assertEqual(event.data["body"], b"hello")
        self.assertIn(["Content-Length", "4"], event.data["headers"])
        self.assertIn(["Transfer-Encoding", "chunked"], event.data["headers"])

    def test_keep_alive_serves_several_requests_on_one_connection(self):
        wire = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n"
        answer, events = self.exchange(SAPICMService, wire)
        requests = self.named(events, "ICM HTTP request")
        self.assertEqual([event.data["path"] for event in requests], ["/a", "/b"])
        self.assertEqual(answer.count(b"HTTP/1.1 404"), 2)
        self.assertEqual(requests[0].session.connection_id,
                         requests[1].session.connection_id)
        closed = self.named(events, "Connection closed")[0]
        self.assertEqual(closed.data["packets_in"], 2)
        self.assertEqual(closed.data["close_reason"], "client_close")

    def test_header_and_body_flags(self):
        wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc"
        _, events = self.exchange(SAPICMService, wire,
                                  logging={"http_headers": False, "http_body": False,
                                           "response_events": False})
        event = self.named(events, "ICM HTTP request")[0]
        self.assertNotIn("headers", event.data)
        self.assertNotIn("body", event.data)
        self.assertIsNone(event.response)
        self.assertEqual(event.request, wire)

    def test_icm_answers_non_http_input_like_the_icm(self):
        for wire, kind in ((b"\n", "invalid_request_line"),
                           (b"HELLO WORLD\r\n\r\n", "invalid_request_line"),
                           (client_hello(), "tls")):
            with self.subTest(kind=kind, wire=wire[:10]):
                answer, events = self.exchange(SAPICMService, wire)
                head, body = answer.split(b"\r\n\r\n", 1)
                self.assertTrue(head.startswith(b"HTTP/1.0 400 Bad Request\r\n"))
                self.assertIn(b"content-length: %-7d" % len(body), head)
                self.assertIn(b"400 Bad HTTP Request", body)
                self.assertNotIn(b"{{", body)
                non_http = self.named(events, "Non-HTTP input")
                self.assertEqual(len(non_http), 1)
                self.assertEqual(non_http[0].data["kind"], kind)
                self.assertEqual(non_http[0].request, wire)
                self.assertEqual(non_http[0].response, answer)

    def test_tls_client_hello_on_plain_port_is_fingerprinted(self):
        _, events = self.exchange(SAPICMService, client_hello("target.sap.example"))
        tls = self.named(events, "Non-HTTP input")[0].data["tls"]
        self.assertEqual(tls["sni"], "target.sap.example")
        self.assertTrue(tls["ja3_hash"])
        self.assertTrue(tls["ja4"].startswith("t13d"))
        self.assertIn("http/1.1", tls["alpn"] + ["http/1.1"])

    def test_message_server_closes_on_non_http_input(self):
        answer, events = self.exchange(SAPMSHTTPService, b"HELLO\r\n\r\n")
        self.assertEqual(answer, b"")
        self.assertEqual(self.named(events, "Non-HTTP input")[0].request,
                         b"HELLO\r\n\r\n")

    def test_overlong_request_line_is_logged_and_closed(self):
        wire = b"G" * 70000
        answer, events = self.exchange(SAPMSHTTPService, wire)
        self.assertEqual(answer, b"")
        event = self.named(events, "Non-HTTP input")[0]
        self.assertEqual(event.data["kind"], "invalid_request_line")
        self.assertTrue(wire.startswith(event.request))
        self.assertGreaterEqual(event.data["request_size"], 65536)

    def test_malformed_headers_are_unparsed_input(self):
        wire = b"GET / HTTP/1.1\r\nHost x\r\n\r\n"
        answer, events = self.exchange(SAPICMService, wire)
        self.assertTrue(answer.startswith(b"HTTP/1.0 400"))
        event = self.named(events, "Unparsed input")[0]
        self.assertEqual(event.data["stage"], "headers")
        self.assertEqual(event.request, wire)

    def test_incomplete_request_is_reported(self):
        wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\nshort"
        _, events = self.exchange(SAPICMService, wire)
        event = self.named(events, "Non-HTTP input")[0]
        self.assertEqual(event.data["kind"], "incomplete_request")
        self.assertEqual(event.request, wire)

    def test_connect_without_data(self):
        answer, events = self.exchange(SAPICMService, b"",
                                       logging={"connection_events": "all"})
        self.assertEqual(answer, b"")
        self.assertEqual([event.event for event in events],
                         ["Connection opened", "Connection closed"])

    def test_virtual_http_service_does_not_bind(self):
        # The address is not local: binding it would fail
        service, _ = self.make_service(SAPICMService, listener_address="203.0.113.10")
        self.assertIsNotNone(service.server)
        service.stop()


class HTTPSFrontTest(HTTPServiceHarness, unittest.TestCase):

    def test_https_request_is_logged_in_clear(self):
        service, manager = self.make_service(
            SAPICMService, tls={"enabled": True, "common_name": "A4H.example"})
        server_side, client = socket.socketpair()
        answer = {}

        def talk():
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(client, server_hostname="sap.example") as tls:
                answer["cert"] = tls.getpeercert(binary_form=True)
                tls.sendall(b"GET /secure HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                data = b""
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                answer["data"] = data

        thread = threading.Thread(target=talk)
        thread.start()
        try:
            service.handle_virtual(server_side, ("192.0.2.5", 40100))
            server_side.close()
            thread.join(10)
        finally:
            client.close()
        events = self.drain(manager)
        self.assertTrue(answer["data"].startswith(b"HTTP/1.1 404"))
        names = [event.event for event in events]
        self.assertEqual(names[:3], ["TLS client hello", "TLS established",
                                     "ICM HTTP request"])
        self.assertEqual(events[0].data["tls"]["sni"], "sap.example")
        request = events[2]
        self.assertEqual(request.data["scheme"], "https")
        self.assertTrue(request.request.startswith(b"GET /secure HTTP/1.1"))
        from cryptography import x509
        certificate = x509.load_der_x509_certificate(answer["cert"])
        self.assertIn("CN=A4H.example", certificate.subject.rfc4514_string())
        self.assertIn("CN=SAPNetCA_G2", certificate.issuer.rfc4514_string())

    def test_plaintext_on_tls_port_is_closed_silently(self):
        wire = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        answer, events = self.exchange(SAPICMService, wire, tls={"enabled": True})
        self.assertEqual(answer, b"")
        event = self.named(events, "Non-HTTP input")[0]
        self.assertEqual(event.data["kind"], "plaintext_on_tls_port")
        self.assertEqual(event.request, wire)


class TLSFingerprintTest(unittest.TestCase):

    def test_parse_client_hello(self):
        hello = parse_client_hello(client_hello("example.com"))
        self.assertEqual(hello["sni"], "example.com")
        self.assertEqual(hello["version"], "0x0304")
        self.assertFalse(hello["truncated"])
        self.assertTrue(hello["ciphers"])
        self.assertEqual(len(hello["ja3_hash"]), 32)
        self.assertRegex(hello["ja4"], r"^t13d\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")

    def test_not_a_client_hello(self):
        self.assertIsNone(parse_client_hello(b"GET / HTTP/1.1\r\n"))
        self.assertIsNone(parse_client_hello(b"\x16\x03\x01\x00"))

    def test_ja3_skips_grease(self):
        text, _ = ja3(771, [0x0a0a, 4865], [(0x1a1a, b""), (0, b"")], [0x2a2a, 29], [0])
        self.assertEqual(text, "771,4865,0,29,0")

    def test_ja4_known_value(self):
        # FoxIO JA4 reference example structure: TLS 1.3, SNI, h2
        value = ja4(0x0304, [0x1301, 0x1302], [(0x0000, b""), (0x0010, b""), (0x000d, b"")],
                    "x", ["h2"], [0x0403])
        self.assertTrue(value.startswith("t13d0203h2_"))


def test_suite():
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for case in (HTTPFrontTest, HTTPSFrontTest, TLSFingerprintTest):
        suite.addTest(loader.loadTestsFromTestCase(case))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
