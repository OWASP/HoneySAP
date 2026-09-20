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
from time import monotonic
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

    def test_event_keywords_and_reuse_across_sessions(self):
        queue = Queue()
        first = Session(queue, "first", "127.0.0.1", 1, "127.0.0.1", 2)
        second = Session(queue, "second", "127.0.0.1", 3, "127.0.0.1", 4)
        first.add_event("with fields", data={"key": ["value"]},
                        request=b"request", response=b"response")
        with_fields = queue.get(timeout=2)
        self.assertEqual(with_fields.data, {"key": ["value"]})
        self.assertEqual(with_fields.request, b"request")
        self.assertEqual(with_fields.response, b"response")
        first.add_event(with_fields)
        second.add_event(with_fields)
        same = queue.get(timeout=2)
        other = queue.get(timeout=2)
        self.assertIsNot(same, with_fields)
        self.assertIs(same.session, first)
        self.assertIs(other.session, second)
        self.assertIs(with_fields.session, first)
        self.assertIsNot(other, with_fields)
        self.assertEqual(other.data, with_fields.data)
        self.assertEqual(same.timestamp, with_fields.timestamp)
        self.assertEqual(other.timestamp, with_fields.timestamp)
        other.data["key"].append("second")
        self.assertEqual(with_fields.data, {"key": ["value"]})
        self.assertEqual(same.data, {"key": ["value"]})


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
        self.assertIs(session,
                      session_manager.get_session("test", "127.0.0.1", 3200,
                                                  "127.0.0.1", 3201))
        self.assertIsNotNone(session.campaign_uuid)
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

    def test_campaigns_expiry_and_bounded_delivery(self):
        manager = SessionManager(Configuration({
            "event_queue_maxsize": 1,
            "session_ttl_seconds": 1,
            "campaign_window_seconds": 60,
        }))
        first = manager.get_session("one", "192.0.2.1", 1, "127.0.0.1", 2)
        second = manager.get_session("two", "192.0.2.1", 3, "127.0.0.1", 4)
        self.assertEqual(first.campaign_uuid, second.campaign_uuid)
        self.assertTrue(first.add_event("first"))
        self.assertFalse(first.add_event("dropped"))
        self.assertEqual(manager.event_queue_metrics(), {
            "accepted": 1, "dropped": 1, "queued": 1, "maxsize": 1,
            "active_sessions": 2, "active_campaigns": 1,
            "evicted_sessions": 0, "evicted_campaigns": 0,
        })
        first.last_activity = monotonic() - 2
        second.last_activity = monotonic() - 2
        self.assertEqual(manager.expire_sessions(), 2)
        self.assertFalse(manager.sessions)

    def test_session_and_campaign_capacity_evicts_oldest_entries(self):
        manager = SessionManager(Configuration({"max_sessions": 2,
                                                "max_campaigns": 2}))
        first = manager.get_session("one", "192.0.2.1", 1, "127.0.0.1", 2)
        first.last_activity = monotonic() - 10
        manager.get_session("two", "192.0.2.2", 1, "127.0.0.1", 2)
        manager.get_session("three", "192.0.2.3", 1, "127.0.0.1", 2)
        self.assertEqual(len(manager.sessions), 2)
        self.assertEqual(len(manager.campaigns), 2)
        self.assertEqual(manager.evicted_sessions, 1)
        self.assertEqual(manager.evicted_campaigns, 1)


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(SessionTest))
    suite.addTest(loader.loadTestsFromTestCase(SessionManagerTest))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
