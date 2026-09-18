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
from unittest.mock import patch
# External imports
from gevent import spawn
from gevent.queue import Queue
# Custom imports
from honeysap.core.event import Event
from honeysap.core.config import Configuration
from honeysap.core.session import SessionManager
from honeysap.core.feed import BaseFeed, FeedManager
from honeysap.core.loader import ClassLoader
from honeysap.feeds.dbfeed import DBFeed


class DummyFeed(BaseFeed):

    def setup(self):
        self.events = Queue()

    def log(self, event):
        self.events.put(event)

    def consume(self, queue):
        pass


class FeedManagerTest(unittest.TestCase):

    def test_failed_feed_setup_closes_previously_loaded_feeds(self):
        class TrackingFeed(DummyFeed):
            def setup(self):
                super().setup()
                self.stop_count = 0

            def stop(self):
                self.stop_count += 1

        class FailingSetupFeed(DummyFeed):
            def setup(self):
                raise ValueError("synthetic setup failure")

        config = Configuration({"feeds": [{"feed": "TrackingFeed", "enabled": True},
                                        {"feed": "FailingSetupFeed", "enabled": True}]})
        manager = FeedManager(config, SessionManager(config))
        with patch("honeysap.core.feed.ClassLoader") as loader:
            loader.return_value.load.return_value = [
                ("TrackingFeed", TrackingFeed),
                ("FailingSetupFeed", FailingSetupFeed)]
            with self.assertRaisesRegex(ValueError, "synthetic setup failure"):
                manager.load_feeds()
        self.assertEqual(len(manager.feeds), 1)
        self.assertEqual(manager.feeds[0].stop_count, 1)
        self.assertTrue(manager.stopped.is_set())

    def test_load_feeds_selects_only_enabled_configurations(self):
        config = Configuration({"feeds": [{"feed": "DummyFeed", "enabled": False},
                                        {"feed": "DummyFeed", "enabled": True},
                                        {"feed": "OtherFeed", "enabled": True}]})
        manager = FeedManager(config, SessionManager(config))
        with patch("honeysap.core.feed.ClassLoader") as loader:
            loader.return_value.load.return_value = [("DummyFeed", DummyFeed)]
            manager.load_feeds()
        self.assertEqual(len(manager.feeds), 1)
        self.assertIsInstance(manager.feeds[0], DummyFeed)
        self.assertTrue(manager.feeds[0].config.get("enabled"))
        manager.stop()

    def test_builtin_feed_loader_preserves_class_identity(self):
        loader = ClassLoader([BaseFeed], "honeysap/feeds")
        self.assertIs(loader.find("DBFeed"), DBFeed)

    def test_real_feed_configuration_loads_canonical_backend(self):
        config = Configuration({"feeds": [{"feed": "DBFeed", "enabled": True,
                                            "db_engine": "sqlite:///:memory:"}]})
        manager = FeedManager(config, SessionManager(config))
        manager.load_feeds()
        try:
            self.assertEqual(len(manager.feeds), 1)
            self.assertIsInstance(manager.feeds[0], DBFeed)
        finally:
            manager.stop()

    def test_feed_manager(self):
        """Test attack feed manager"""

        # Create a session manager and the feed manager attached to it
        config = Configuration()
        session_manager = SessionManager(config)
        feed_manager = FeedManager(config, session_manager)
        feed = DummyFeed(config)
        feed_manager.add_feed(feed)
        workers = []

        def tracked_spawn(callback):
            worker = spawn(callback)
            workers.append(worker)
            return worker

        with patch("honeysap.core.feed.spawn", tracked_spawn):
            feed_manager.run()

        # Create an event
        event = Event("Test event")

        # Obtain a session and add the event
        session = session_manager.get_session("test", "127.0.0.1", 3200, "127.0.0.1", 3201)
        session.add_event(event)

        try:
            # A bounded receipt is deterministic and fails instead of hanging.
            self.assertIs(event, feed.events.get(timeout=2))
        finally:
            feed_manager.stop()
            workers[0].join(timeout=2)
        self.assertTrue(workers[0].dead)


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(FeedManagerTest))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
