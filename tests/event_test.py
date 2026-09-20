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
import json
import unittest
from base64 import b64encode
from datetime import date
# External imports
from gevent.queue import Queue
# Custom imports
from honeysap.core.event import Event
from honeysap.core.session import Session


class EventTest(unittest.TestCase):

    test_string = "Test"

    def test_event(self):
        """Test the attack event object"""

        event = Event(self.test_string, data=self.test_string)

        with self.assertRaises(Exception):
            str(event)
        with self.assertRaises(Exception):
            repr(event)

        session = Session(Queue(), "test", "127.0.0.1", 3200, "127.0.0.1", 3201)
        session.add_event(event)

        event_json = json.loads(repr(event))
        self.assertEqual(event_json["schema_version"], Event.schema_version)
        self.assertEqual(event_json["event_id"], str(event.uuid))
        self.assertEqual(event_json["sequence"], 1)
        self.assertEqual(event_json["event"], event.event)
        self.assertEqual(event_json["data"], event.data)
        self.assertEqual(event_json["timestamp"], event.timestamp.isoformat())
        self.assertEqual(event_json["session"], str(session.uuid))
        self.assertEqual(event_json["campaign"], str(session.campaign_uuid))
        self.assertEqual(event_json["service"], session.service)
        self.assertEqual(event_json["source_ip"], session.source_ip)
        self.assertEqual(event_json["source_port"], session.source_port)
        self.assertEqual(event_json["target_ip"], session.target_ip)
        self.assertEqual(event_json["target_port"], session.target_port)

    def test_payload_fields_and_nested_data(self):
        session = Session(Queue(), "test", "127.0.0.1", 3200,
                          "127.0.0.1", 3201)
        event = Event("payload", data={"items": [b"hello", b"\xff\xfe", None,
                                               {"tuple": (b"world", 3)}]},
                      request=b"\x00\xff", response="é", session=session)
        payload = json.loads(repr(event))
        self.assertEqual(payload["request"], b64encode(b"\x00\xff").decode())
        self.assertEqual(payload["response"], b64encode("é".encode()).decode())
        self.assertEqual(payload["data"]["items"],
                         [{"type": "bytes", "encoding": "base64",
                           "value": b64encode(b"hello").decode()},
                          {"type": "bytes", "encoding": "base64",
                           "value": b64encode(b"\xff\xfe").decode()}, "",
                          {"tuple": [{"type": "bytes", "encoding": "base64",
                                      "value": b64encode(b"world").decode()}, 3]}])

    def test_unusual_event_data_is_serialized_without_losing_binary_type(self):
        session = Session(Queue(), "test", "127.0.0.1", 1,
                          "127.0.0.1", 2)
        event = Event("unusual", data={"bytearray": bytearray(b"raw"),
                                        "memoryview": memoryview(b"evidence"),
                                        "date": date(2026, 1, 2),
                                        "object": object()}, session=session)
        data = json.loads(repr(event))["data"]
        self.assertEqual(data["bytearray"], {"type": "bytes", "encoding": "base64",
                                             "value": b64encode(b"raw").decode()})
        self.assertEqual(data["memoryview"], {"type": "bytes", "encoding": "base64",
                                              "value": b64encode(b"evidence").decode()})
        self.assertEqual(data["date"], {"type": "date", "value": "2026-01-02"})
        self.assertEqual(data["object"]["type"], "repr")

    def test_empty_request_and_response(self):
        event = Event("empty", session=Session(Queue(), "test", "127.0.0.1",
                                               1, "127.0.0.1", 2))
        payload = json.loads(repr(event))
        self.assertEqual(payload["request"], "")
        self.assertEqual(payload["response"], "")

    def test_falsy_data_keeps_its_json_type(self):
        session = Session(Queue(), "test", "127.0.0.1", 1,
                          "127.0.0.1", 2)
        for value, expected in ((0, 0), (False, False), ([], []), ({}, {}),
                                (None, "")):
            with self.subTest(value=value):
                event = Event("falsy", data=value, session=session)
                self.assertEqual(json.loads(repr(event))["data"], expected)
        event = Event("nested", data={"zero": 0, "false": False,
                                      "list": [], "dict": {}}, session=session)
        self.assertEqual(json.loads(repr(event))["data"], event.data)


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(EventTest))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
