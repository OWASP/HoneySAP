# ===========
# HoneySAP - SAP low-interaction honeypot
#
# Copyright (C) 2015 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security.
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
# ==============

# Standard imports
import json
import unittest
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


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(EventTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
