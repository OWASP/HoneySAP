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
import sqlite3
import unittest
from unittest.mock import Mock, patch
from os import close, remove
from os.path import exists
from tempfile import mkstemp
# External imports
from gevent.queue import Queue
# Custom imports
from honeysap.core.event import Event
from honeysap.feeds.dbfeed import DBEvent, DBFeed
from honeysap.core.session import Session
from honeysap.core.config import Configuration


class DBFeedsTest(unittest.TestCase):

    def test_setup_disposes_engine_on_schema_failure(self):
        engine = Mock()
        with patch("honeysap.feeds.dbfeed.create_engine", return_value=engine):
            with patch("honeysap.feeds.dbfeed.Base.metadata.create_all",
                       side_effect=ValueError("schema failure")):
                with self.assertRaisesRegex(ValueError, "schema failure"):
                    DBFeed(Configuration({"db_engine": "sqlite:///:memory:"}))
        engine.dispose.assert_called_once()

    def test_failed_commit_rolls_back_and_next_event_succeeds(self):
        feed = DBFeed(Configuration({"db_engine": "sqlite:///:memory:"}))
        session = Session(Queue(), "test", "127.0.0.1", 1,
                          "127.0.0.1", 2)
        first = Event("first", session=session)
        second = Event("second", session=session)
        try:
            with patch.object(feed.session, "commit", side_effect=ValueError("commit failed")):
                with patch.object(feed.session, "rollback",
                                  wraps=feed.session.rollback) as rollback:
                    with self.assertRaisesRegex(ValueError, "commit failed"):
                        feed.log(first)
                    rollback.assert_called_once()
            feed.log(second)
            rows = feed.session.query(DBEvent).all()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].event, repr(second))
        finally:
            feed.stop()

    def test_dispose_even_when_session_close_fails(self):
        feed = DBFeed(Configuration({"db_engine": "sqlite:///:memory:"}))
        with patch.object(feed.session, "close", side_effect=ValueError("close failed")):
            with patch.object(feed.engine, "dispose") as dispose:
                with self.assertRaisesRegex(ValueError, "close failed"):
                    feed.stop()
        dispose.assert_called_once()

    def test_dbfeeds(self):
        """Tests event storage on a database"""

        descriptor, self.test_filename = mkstemp(".sqlite", "dbfeedstest")
        close(descriptor)

        # Register an event using the DBFeed
        configuration = Configuration({"feed": "DBFeed",
                                       "db_engine": "sqlite:///%s" % self.test_filename})
        feed = DBFeed(configuration)
        self.assertFalse(feed.supports_consumption)
        with self.assertRaises(NotImplementedError):
            feed.consume(Queue())
        event = Event("Test event")
        event.session = Session(Queue(), "test", "127.0.0.1", 3200,
                                "127.0.0.1", 3201)
        feed.log(event)
        with patch.object(feed.engine, "dispose", wraps=feed.engine.dispose) as dispose:
            feed.stop()
        dispose.assert_called_once()

        # Now check the event in the database
        conn = sqlite3.connect(self.test_filename)
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM events')
            results = cursor.fetchall()

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0][1], str(event.session.uuid))
            self.assertEqual(results[0][2],
                             str(event.timestamp.replace(tzinfo=None)))
            self.assertEqual(results[0][3], repr(event))
        finally:
            conn.close()

    def tearDown(self):
        if hasattr(self, "test_filename") and exists(self.test_filename):
            remove(self.test_filename)


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(DBFeedsTest))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
