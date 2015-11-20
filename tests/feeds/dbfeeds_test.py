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
import sqlite3
import unittest
from os import remove
from os.path import exists
from tempfile import mkstemp
# External imports
from gevent.queue import Queue
# Custom imports
from honeysap.core.event import Event
from honeysap.feeds.dbfeed import DBFeed
from honeysap.core.session import Session
from honeysap.core.config import Configuration


class DBFeedsTest(unittest.TestCase):

    def test_dbfeeds(self):
        """Tests event storage on a database"""

        self.test_filename = mkstemp(".sqlite", "dbfeedstest")[1]

        # Register an event using the DBFeed
        configuration = Configuration({"feed": "DBFeed",
                                       "db_engine": "sqlite:///%s" % self.test_filename})
        feed = DBFeed(configuration)
        event = Event("Test event")
        event.session = Session(Queue(), "test", "127.0.0.1", 3200,
                                "127.0.0.1", 3201)
        feed.log(event)
        feed.stop()

        # Now check the event in the database
        conn = sqlite3.connect(self.test_filename)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM events')
        results = cursor.fetchall()

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1], str(event.session.uuid))
        self.assertEqual(results[0][2], str(event.timestamp))
        self.assertEqual(results[0][3], repr(event))

    def tearDown(self):
        if exists(self.test_filename):
            remove(self.test_filename)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(DBFeedsTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
