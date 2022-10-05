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
# External imports
from hpfeeds import new as new_hpc
# Custom imports
from honeysap.core.feed import BaseFeed


class HPFeed(BaseFeed):
    """ HPFeeds based feed class
    """

    @property
    def feed_host(self):
        return self.config.get("feed_host")

    @property
    def feed_port(self):
        return self.config.get("feed_port")

    @property
    def ident(self):
        return self.config.get("feed_ident")

    @property
    def secret(self):
        return self.config.get("feed_secret")

    @property
    def feed_timeout(self):
        return self.config.get("feed_timeout", None)

    @property
    def channels(self):
        return self.config.get("channels", None)

    def setup(self):
        """Initializes the HPFeed connection"""
        if self.channels is None:
            self.channels = ["honeysap.events"]
        self.hpc = new_hpc(host=self.feed_host,
                           port=self.feed_port,
                           ident=self.ident,
                           secret=self.secret,
                           timeout=self.feed_timeout)
        self.logger.debug("Connected to HPFeeds server (%s:%s - %s)",
                          self.feed_host, self.feed_port, self.ident)

    def stop(self):
        """Stops the HPFeed connection"""
        self.hpc.close()
        self.logger.debug("Closed communication with HPFeeds server (%s:%s - %s)",
                          self.feed_host, self.feed_port, self.ident)

    def log(self, event):
        """Log an event to the feed"""
        self.hpc.publish(self.channels, repr(event))

    def consume(self, queue):
        """Setup the feed to subscribe to the HPFeed and put the events on
        a queue."""

        def on_message(identifier, channel, payload):
            queue.put(payload)

        def on_error(payload):
            self.hpc.stop()

        self.logger.debug("Subscribing to channels %s", self.channels)
        self.hpc.subscribe(self.channels)
        self.hpc.run(on_message, on_error)
