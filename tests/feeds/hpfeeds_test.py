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
from gevent.queue import Queue
# Custom imports
from honeysap.core.event import Event
from honeysap.feeds.hpfeed import HPFeed
from honeysap.core.session import Session
from honeysap.core.config import Configuration


class HPFeedsTest(unittest.TestCase):

    # Test account on HPFriends service for checking connectivity
    test_host = "hpfriends.honeycloud.net"
    test_port = 20000
    test_ident = "H9YUEy6w"
    test_secret = "NNKg4vkYzJ09eDWX"
    test_channel = "test"

    def test_hpfeeds(self):
        """Tests the HPFeed by connecting to honeynet's HPFriends service.
        """

        # Register an event using the HPFeed
        configuration = Configuration({"feed": "HPFeed",
                                       "feed_host": self.test_host,
                                       "feed_port": self.test_port,
                                       "feed_ident": self.test_ident,
                                       "feed_secret": self.test_secret,
                                       "channels": [self.test_channel]})
        #feed = HPFeed(configuration)
        #event = Event("Test event")
        #event.session = Session(Queue(), "test", "127.0.0.1", 3200,
        #                        "127.0.0.1", 3201)

        #feed.log(event)
        #feed.stop()


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(HPFeedsTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
