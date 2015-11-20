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
import unittest
from os import path, remove
from tempfile import mkstemp
# External imports
from gevent.queue import Queue
# Custom imports
from honeysap.core.event import Event
from honeysap.core.session import Session
from honeysap.feeds.logfeed import LogFeed
from honeysap.core.config import Configuration


class LogFeedsTest(unittest.TestCase):

    def __init__(self, args):
        super(LogFeedsTest, self).__init__(args)

    def test_logfeeds(self):

        self.test_filename = mkstemp(".log", "logfeedstest")[1]

        # Register an event using the LogFeed
        configuration = Configuration({"feed": "LogFeed",
                                       "log_filename": self.test_filename})
        feed = LogFeed(configuration)
        event = Event("Test event")
        event.session = Session(Queue(), "test", "127.0.0.1", 3200,
                                "127.0.0.1", 3201)

        feed.log(event)
        feed.stop()

        self.assertIs(path.exists(self.test_filename), True)

    def tearDown(self):
        if path.exists(self.test_filename):
            remove(self.test_filename)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(LogFeedsTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
