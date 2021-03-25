# ===========
# HoneySAP - SAP low-interaction honeypot
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# The library was designed and developed by Martin Gallo from
# the SecureAuth's Innovation Labs team.
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
import unittest
# External imports
from gevent.hub import sleep
from gevent.queue import Queue
# Custom imports
from honeysap.core.event import Event
from honeysap.core.config import Configuration
from honeysap.core.session import SessionManager
from honeysap.core.feed import BaseFeed, FeedManager


class DummyFeed(BaseFeed):

    events = Queue()

    def log(self, event):
        self.events.put(event)

    def consume(self, queue):
        pass


class FeedManagerTest(unittest.TestCase):

    def test_feed_manager(self):
        """Test attack feed manager"""

        # Create a session manager and the feed manager attached to it
        config = Configuration()
        session_manager = SessionManager(config)
        feed_manager = FeedManager(config, session_manager)
        feed_manager.add_feed(DummyFeed(config))
        feed_manager.run()

        # Create an event
        event = Event("Test event")

        # Obtain a session and add the event
        session = session_manager.get_session("test", "127.0.0.1", 3200, "127.0.0.1", 3201)
        session.add_event(event)

        # Give the feed manager time for processing the event
        sleep(1)

        # Stop the feed manager and check if the event was processed
        feed_manager.stop()
        new_event = DummyFeed.events.get()
        self.assertIs(event, new_event)


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(FeedManagerTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
