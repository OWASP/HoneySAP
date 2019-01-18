# ===========
# HoneySAP - SAP low-interaction honeypot
#
# SECUREAUTH LABS. Copyright (C) 2019 SecureAuth Corporation. All rights reserved.
#
# The library was designed and developed by Martin Gallo from
# the SecureAuth Labs team.
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
from threading import Event
from abc import abstractmethod, ABCMeta
# External imports
from gevent import spawn
from gevent.queue import Empty, Queue
# Custom imports
from .logger import Loggeable
from .loader import ClassLoader


class BaseFeed(Loggeable):
    """ Base attack feed class
    """

    __metaclass__ = ABCMeta

    def __init__(self, config):
        """Initialize the attack session feed with the options provided.
        """
        super(BaseFeed, self).__init__()
        self.config = config
        self.setup()
        self.logger.debug("Feed initialized")

    def setup(self):
        """Setup the feed (e.g. initializes connection)"""
        pass

    def stop(self):
        """Close the feed"""
        pass

    @abstractmethod
    def log(self, event):
        """Log an event in the attack session feed"""
        pass

    @abstractmethod
    def consume(self):
        """Consume events from the attack session feed"""
        pass


class FeedManager(Loggeable):
    """ Feed manager class
    """

    feeds_path = "honeysap/feeds"

    def __init__(self, config, session_manager):
        """Initialize the feed manager.
        """
        self.config = config
        self.feeds = []
        self.stopped = Event()
        self.session_manager = session_manager
        self.logger.debug("Feeds manager initialized")

    def add_feed(self, feed):
        """Add a feed processor to the feed manager."""
        self.feeds.append(feed)
        self.logger.debug("Added feed %s to feed manager", feed._logger_name)

    def load_feeds(self):
        """Loads all the feeds in the configuration."""

        loader = ClassLoader([BaseFeed], self.feeds_path)
        # TODO: Add setup of feeds
        for feed_classname, feed_cls in loader.load():
            self.logger.debug("Found feed %s, looking for configuration",
                              feed_classname)

            feeds_configs = self.config.config_for("feeds", "feed", feed_classname)
            self.logger.debug("Found %d configuration(s) for %s",
                              len(feeds_configs),
                              feed_classname)

            for feed_config in feeds_configs:
                if feed_config.get("enabled", False):
                    self.add_feed(feed_cls(feed_config))

    def run(self):
        """Start the feed manager by processing events in the session manager."""
        spawn(self.process_events)

    def stop(self):
        """Stop the feed manager processing and all the feeds attached."""
        if not self.stopped.is_set():
            for feed in self.feeds:
                feed.stop()
            self.stopped.set()

    def process_events(self):
        """Process events on the session manager event queue."""
        while not self.stopped.is_set():
            try:
                # Obtain the next event to process
                event = self.session_manager.event_queue.get()
                self.logger.debug("Processing event '%s'", event)
                for feed in self.feeds:
                    # Try to process the event with all the feeds. If a feed
                    # fails, log the exception and continue with the rest of
                    # the feeds
                    try:
                        feed.log(event)
                    except Exception:
                        self.logger.exception("Feed failed at processing event '%s'" % event)
            except Empty:
                pass

    def consume_events(self, callback):
        """Consume events in a feed."""

        # Setup a queue and start feeds consuming and putting events there.
        # Each feed consumes events on his own greenlet.
        event_queue = Queue()
        for feed in self.feeds:
            spawn(feed.consume, event_queue)

        self.logger.debug("Feeds started consuming events")
        while not self.stopped.is_set():
            try:
                # Get an event from the queue
                event = event_queue.get()

                # Try to run the callback for producing the eater output
                try:
                    callback(event)
                except Exception:
                    self.logger.exception("Eater failed at processing event '%s'" % event)

            except Empty:
                pass
