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

import io
import unittest
from unittest.mock import patch

from gevent.queue import Queue

from honeysap.core.config import Configuration
from honeysap.core.event import Event
from honeysap.core.session import Session
from honeysap.feeds.consolefeed import ConsoleFeed


class ConsoleFeedsTest(unittest.TestCase):

    def test_default_config_logs_and_removes_handler(self):
        output = io.StringIO()
        with patch("honeysap.feeds.consolefeed.sys.stdout", output):
            feed = ConsoleFeed(Configuration())
        self.assertFalse(feed.supports_consumption)
        with self.assertRaises(NotImplementedError):
            feed.consume(Queue())
        try:
            event = Event("console", session=Session(Queue(), "test",
                                                     "127.0.0.1", 1,
                                                     "127.0.0.1", 2))
            feed.log(event)
            self.assertIn(repr(event), output.getvalue())
        finally:
            feed.stop()
        self.assertNotIn(feed.stream_handler, feed.feed_logger.handlers)
        logged = output.getvalue()
        feed.log(event)
        self.assertEqual(output.getvalue(), logged)


def test_suite():
    return unittest.TestLoader().loadTestsFromTestCase(ConsoleFeedsTest)


test_suite.__test__ = False
