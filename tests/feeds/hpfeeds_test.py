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
from unittest.mock import Mock, patch
# External imports
from gevent.queue import Queue
# Custom imports
from honeysap.core.event import Event
from honeysap.feeds.hpfeed import HPFeed
from honeysap.core.session import Session
from honeysap.core.config import Configuration


class HPFeedsTest(unittest.TestCase):

    def test_hpfeeds(self):
        """Publish and consume through a mocked hpfeeds connection."""
        connection = Mock()
        config = Configuration({"feed_host": "example.invalid", "feed_port": 20000,
                                "feed_ident": "ident", "feed_secret": "secret",
                                "channels": ["test"]})
        with patch("honeysap.feeds.hpfeed.new_hpc", return_value=connection) as connect:
            feed = HPFeed(config)
        connect.assert_called_once_with(host="example.invalid", port=20000,
                                        ident="ident", secret="secret", timeout=None)
        event = Event("Test event")
        event.session = Session(Queue(), "test", "127.0.0.1", 3200,
                                "127.0.0.1", 3201)
        feed.log(event)
        connection.publish.assert_called_once_with(["test"], repr(event))

        received = Queue()
        def send_message(on_message, on_error):
            on_message("ident", "test", b"payload")
        connection.run.side_effect = send_message
        feed.consume(received)
        connection.subscribe.assert_called_once_with(["test"])
        self.assertEqual(received.get(timeout=2), b"payload")
        def send_error(on_message, on_error):
            on_error(b"error")
        connection.run.side_effect = send_error
        feed.consume(Queue())
        connection.stop.assert_called_once()
        feed.stop()
        connection.close.assert_called_once()

    def test_default_channels(self):
        connection = Mock()
        with patch("honeysap.feeds.hpfeed.new_hpc", return_value=connection) as connect:
            feed = HPFeed(Configuration({"feed_timeout": 5}))
        self.assertEqual(connect.call_args.kwargs["timeout"], 5)
        self.assertEqual(feed.channels, ["honeysap.events"])
        event = Event("default", session=Session(Queue(), "test", "127.0.0.1",
                                                1, "127.0.0.1", 2))
        feed.log(event)
        connection.publish.assert_called_once_with(["honeysap.events"], repr(event))
        feed.stop()


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(HPFeedsTest))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
