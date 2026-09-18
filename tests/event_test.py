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
        self.assertEqual(event_json["event"], event.event)
        self.assertEqual(event_json["data"], event.data)
        self.assertEqual(event_json["timestamp"], str(event.timestamp))
        self.assertEqual(event_json["session"], str(session.uuid))
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
                         ["hello", b64encode(b"\xff\xfe").decode(), "",
                          {"tuple": ["world", 3]}])

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
