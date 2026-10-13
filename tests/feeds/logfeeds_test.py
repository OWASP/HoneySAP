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
import os
import unittest
from os import close, path, remove
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

        descriptor, self.test_filename = mkstemp(".log", "logfeedstest")
        close(descriptor)

        # Register an event using the LogFeed
        configuration = Configuration({"feed": "LogFeed",
                                       "log_filename": self.test_filename})
        feed = LogFeed(configuration)
        self.assertFalse(feed.supports_consumption)
        with self.assertRaises(NotImplementedError):
            feed.consume(Queue())
        event = Event("Test event")
        event.session = Session(Queue(), "test", "127.0.0.1", 3200,
                                "127.0.0.1", 3201)

        feed.log(event)
        feed.stop()

        with open(self.test_filename, encoding="utf-8") as log_file:
            logged = log_file.read()
        self.assertIn(repr(event), logged)

    def test_logfeed_follows_external_rotation(self):
        descriptor, self.test_filename = mkstemp(".log", "logfeedstest")
        close(descriptor)
        feed = LogFeed(Configuration({"feed": "LogFeed", "log_filename": self.test_filename}))
        event = Event("Before rotation")
        event.session = Session(Queue(), "test", "127.0.0.1", 3200, "127.0.0.1", 3201)
        feed.log(event)
        os.rename(self.test_filename, self.test_filename + ".1")
        event = Event("After rotation")
        event.session = Session(Queue(), "test", "127.0.0.1", 3200, "127.0.0.1", 3201)
        feed.log(event)
        feed.log_metrics({"accepted": 2, "feeds": {}})
        feed.stop()
        with open(self.test_filename + ".1", encoding="utf-8") as log_file:
            self.assertIn("Before rotation", log_file.read())
        with open(self.test_filename, encoding="utf-8") as log_file:
            logged = log_file.read()
        self.assertIn("After rotation", logged)
        self.assertIn("Metrics " + json.dumps({"accepted": 2, "feeds": {}}), logged)
        remove(self.test_filename + ".1")

    def test_logfeed_rotates_by_size(self):
        descriptor, self.test_filename = mkstemp(".log", "logfeedstest")
        close(descriptor)
        feed = LogFeed(Configuration({"feed": "LogFeed", "log_filename": self.test_filename,
                                      "max_bytes": 2000, "backup_count": 2}))
        for number in range(30):
            event = Event("Event %d" % number)
            event.session = Session(Queue(), "test", "127.0.0.1", 3200, "127.0.0.1", 3201)
            feed.log(event)
        feed.stop()
        self.assertTrue(path.exists(self.test_filename + ".1"))
        self.assertFalse(path.exists(self.test_filename + ".3"))
        self.assertLessEqual(path.getsize(self.test_filename), 2000)
        for suffix in (".1", ".2"):
            if path.exists(self.test_filename + suffix):
                remove(self.test_filename + suffix)

    def test_logfeed_rotation_options_are_checked(self):
        self.test_filename = os.devnull
        for options in ({"max_bytes": -1}, {"max_bytes": 10, "rotate_when": "midnight"},
                        {"backup_count": "x"}):
            with self.assertRaises(ValueError):
                LogFeed(Configuration(dict({"feed": "LogFeed",
                                            "log_filename": os.devnull}, **options)))

    def tearDown(self):
        if self.test_filename != os.devnull and path.exists(self.test_filename):
            remove(self.test_filename)


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(LogFeedsTest))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
