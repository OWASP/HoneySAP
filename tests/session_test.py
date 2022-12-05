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
import unittest
# External imports
from gevent.queue import Queue
# Custom imports
from honeysap.core.event import Event
from honeysap.core.config import Configuration
from honeysap.core.session import Session, SessionManager


class SessionTest(unittest.TestCase):

    def test_session(self):
        """Test the attack session object"""
        queue = Queue()
        session = Session(queue, "test", "127.0.0.1", 3200, "127.0.0.1", 3201)
        event_str = "Some event"

        # Test adding an event object
        event = Event(event_str)
        session.add_event(event)

        new_event = queue.get()
        self.assertIs(new_event, event)
        self.assertIs(new_event.session, session)

        # Test adding an event string
        session.add_event(event_str)

        new_event = queue.get()
        self.assertIs(new_event.session, session)
        self.assertIsInstance(new_event, Event)
        self.assertEqual(new_event.event, event_str)


class SessionManagerTest(unittest.TestCase):

    def test_session_manager(self):
        """Test session manager"""

        # Obtain a session from the manager
        session_manager = SessionManager(Configuration())
        session = session_manager.get_session("test", "127.0.0.1", 3200, "127.0.0.1", 3201)
        # Check that the session obtained matches with the requested data
        self.assertIsInstance(session, Session)
        self.assertIs(session.event_queue, session_manager.event_queue)
        self.assertEqual(session.service, "test")
        self.assertEqual(session.source_ip, "127.0.0.1")
        self.assertEqual(session.source_port, 3200)
        self.assertEqual(session.target_ip, "127.0.0.1")
        self.assertEqual(session.target_port, 3201)
        # Check that different sessions are created for other service/ip/ports
        another_session = session_manager.get_session("test", "127.0.0.1", 3200, "127.0.0.1", 3202)
        self.assertIsNot(session, another_session)
        another_session = session_manager.get_session("test", "127.0.0.1", 3200, "127.0.0.2", 3201)
        self.assertIsNot(session, another_session)
        another_session = session_manager.get_session("test", "127.0.0.2", 3200, "127.0.0.1", 3201)
        self.assertIsNot(session, another_session)
        another_session = session_manager.get_session("test", "127.0.0.1", 3201, "127.0.0.1", 3201)
        self.assertIsNot(session, another_session)
        another_session = session_manager.get_session("service", "127.0.0.1", 3201, "127.0.0.1", 3201)
        self.assertIsNot(session, another_session)


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(SessionTest))
    suite.addTest(loader.loadTestsFromTestCase(SessionManagerTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
