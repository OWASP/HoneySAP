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
from threading import Event
from time import monotonic
from abc import abstractmethod, ABCMeta
# External imports
from gevent import getcurrent, spawn
from gevent.queue import Empty, Full, Queue
# Custom imports
from .logger import Loggeable
from .loader import ClassLoader

# Wake idle consumers periodically so stop() needs no queue-specific sentinel.
QUEUE_WAIT_TIMEOUT = 0.1
WORKER_STOP_TIMEOUT = 2


class BaseFeed(Loggeable, metaclass=ABCMeta):
    """ Base attack feed class
    """

    supports_consumption = True

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
    def consume(self, queue):
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
        self.worker = None
        self.feed_workers = []
        self.feed_queues = {}
        self.feed_delivery = {}
        self.consumers = []
        self.cleanup_worker = None
        self._stop_requester = None
        self._stop_error = None
        self._stop_error_reported = False
        self.session_manager = session_manager
        self.processed_events = 0
        self.feed_errors = 0
        self.logger.debug("Feeds manager initialized")

    def add_feed(self, feed):
        """Add a feed processor to the feed manager."""
        self.feeds.append(feed)
        self.logger.debug("Added feed %s to feed manager", feed._logger_name)

    def load_feeds(self):
        """Loads all the feeds in the configuration."""

        loader = ClassLoader([BaseFeed], self.feeds_path)
        try:
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
        except Exception:
            try:
                self.stop()
            except Exception:
                self.logger.exception("Feed cleanup failed after setup error")
            raise

    def run(self):
        """Start the feed manager by processing events in the session manager."""
        if not self.stopped.is_set() and (self.worker is None or self.worker.dead):
            self._start_feed_workers()
            self.worker = spawn(self.process_events)

    def _start_feed_workers(self):
        maxsize = self.config.get("feed_queue_maxsize", 1000)
        if not isinstance(maxsize, int) or isinstance(maxsize, bool) or maxsize < 1:
            raise ValueError("feed_queue_maxsize must be a positive integer")
        failure_threshold = self.config.get("feed_failure_threshold", 5)
        retry_seconds = self.config.get("feed_retry_seconds", 60)
        if not isinstance(failure_threshold, int) or isinstance(failure_threshold, bool) \
                or failure_threshold < 1:
            raise ValueError("feed_failure_threshold must be a positive integer")
        if not isinstance(retry_seconds, (int, float)) or isinstance(retry_seconds, bool) \
                or retry_seconds < 0:
            raise ValueError("feed_retry_seconds must be a non-negative number")
        self.feed_workers = []
        self.feed_queues = {}
        self.feed_delivery = {}
        feed_ids = set()
        configured_feeds = []
        for index, feed in enumerate(self.feeds, start=1):
            feed_id = feed.config.get("feed_id", "%s-%d" %
                                      (feed.__class__.__name__, index))
            if not isinstance(feed_id, str) or not feed_id:
                raise ValueError("feed_id must be a non-empty string")
            if feed_id in feed_ids:
                raise ValueError("Duplicate feed_id: %s" % feed_id)
            feed_ids.add(feed_id)
            configured_feeds.append((feed, feed_id))
        for feed, feed_id in configured_feeds:
            queue = Queue(maxsize=maxsize)
            self.feed_queues[feed] = queue
            self.feed_delivery[feed] = {"id": feed_id, "delivered": 0,
                                        "dropped": 0, "errors": 0,
                                        "consecutive_errors": 0,
                                        "disabled_until": None,
                                        "skipped": 0, "maxsize": maxsize,
                                        "failure_threshold": failure_threshold,
                                        "retry_seconds": retry_seconds}
            self.feed_workers.append(spawn(self._process_feed, feed, queue))

    def stop(self):
        """Stop the feed manager processing and all the feeds attached."""
        if not self.stopped.is_set():
            self.stopped.set()
            if getcurrent() in self.consumers:
                self._stop_requester = getcurrent()
            self.cleanup_worker = spawn(self._finish_stop)
        # A worker cannot wait for cleanup that first waits for it to exit.
        if getcurrent() is self.worker or getcurrent() in self.feed_workers \
                or getcurrent() in self.consumers:
            return
        if self.cleanup_worker is not None:
            self.cleanup_worker.join()
            if self.cleanup_worker.exception is not None and self._stop_error is None:
                self._stop_error = self.cleanup_worker.exception
            if self._stop_error is not None and not self._stop_error_reported:
                self._stop_error_reported = True
                raise self._stop_error

    def _finish_stop(self):
        # A feed must not be closed while the processing worker logs to it.
        if self.worker is not None:
            self.worker.join(timeout=WORKER_STOP_TIMEOUT)
            if not self.worker.dead:
                self.worker.kill(block=True, timeout=WORKER_STOP_TIMEOUT)
            if not self.worker.dead:
                self._stop_error = RuntimeError("Feed processing worker did not stop")
                return
        for worker in self.feed_workers:
            worker.join(timeout=WORKER_STOP_TIMEOUT)
            if not worker.dead:
                worker.kill(block=True, timeout=WORKER_STOP_TIMEOUT)
            if not worker.dead:
                self._stop_error = RuntimeError("Feed delivery worker did not stop")
                return
        if self._stop_requester is not None:
            self._stop_requester.join(timeout=WORKER_STOP_TIMEOUT)
            if not self._stop_requester.dead:
                self._stop_requester.kill(block=True, timeout=WORKER_STOP_TIMEOUT)
            if not self._stop_requester.dead:
                self._stop_error = RuntimeError("Feed stop requester did not stop")
                return
        first_error = None
        for feed in self.feeds:
            try:
                feed.stop()
            except Exception as error:
                self.logger.exception("Feed failed to stop: %s", feed)
                if first_error is None:
                    first_error = error
        for worker in self.consumers:
            worker.join(timeout=WORKER_STOP_TIMEOUT)
            if not worker.dead:
                worker.kill(block=True, timeout=WORKER_STOP_TIMEOUT)
            if not worker.dead and first_error is None:
                first_error = RuntimeError("Feed consumer worker did not stop")
        self._stop_error = first_error

    def process_events(self):
        """Process events on the session manager event queue."""
        while not self.stopped.is_set():
            try:
                # Obtain the next event to process
                event = self.session_manager.event_queue.get(timeout=QUEUE_WAIT_TIMEOUT)
                self.logger.debug("Processing event '%s'", event)
                self.processed_events += 1
                for feed in self.feeds:
                    delivery = self.feed_delivery[feed]
                    if delivery["disabled_until"] is not None and \
                            monotonic() < delivery["disabled_until"]:
                        delivery["skipped"] += 1
                        continue
                    try:
                        self.feed_queues[feed].put_nowait(event)
                    except Full:
                        self.feed_delivery[feed]["dropped"] += 1
                        self.logger.warning("Feed queue full; dropped event '%s' for %s",
                                            event.event, feed._logger_name)
            except Empty:
                pass

    def metrics(self):
        """Return lightweight delivery and queue-health counters."""
        result = self.session_manager.event_queue_metrics()
        result.update({"processed": self.processed_events,
                       "feed_errors": self.feed_errors,
                       "feeds": {values["id"]: dict(values,
                                                        queued=self.feed_queues[feed].qsize())
                                 for feed, values in self.feed_delivery.items()}})
        return result

    def _process_feed(self, feed, queue):
        while not self.stopped.is_set():
            try:
                event = queue.get(timeout=QUEUE_WAIT_TIMEOUT)
            except Empty:
                continue
            try:
                feed.log(event)
                delivery = self.feed_delivery[feed]
                delivery["delivered"] += 1
                delivery["consecutive_errors"] = 0
                delivery["disabled_until"] = None
            except Exception:
                self.feed_errors += 1
                delivery = self.feed_delivery[feed]
                delivery["errors"] += 1
                delivery["consecutive_errors"] += 1
                if delivery["consecutive_errors"] >= delivery["failure_threshold"]:
                    delivery["disabled_until"] = monotonic() + delivery["retry_seconds"]
                    self.logger.warning("Feed disabled after %d consecutive failures: %s",
                                        delivery["consecutive_errors"], delivery["id"])
                self.logger.exception("Feed failed at processing event '%s'", event)

    def consume_events(self, callback):
        """Consume events in a feed."""

        if self.stopped.is_set():
            return

        self.consumers = [worker for worker in self.consumers if not worker.dead]

        # Setup a queue and start feeds consuming and putting events there.
        # Each feed consumes events on his own greenlet.
        event_queue = Queue()
        started = []
        for feed in self.feeds:
            if feed.supports_consumption:
                started.append(spawn(self._consume_feed, feed, event_queue))

        self.consumers.extend(started)
        if not started:
            return

        self.logger.debug("Feeds started consuming events")
        while not self.stopped.is_set():
            try:
                # Get an event from the queue
                event = event_queue.get(timeout=QUEUE_WAIT_TIMEOUT)

                # Try to run the callback for producing the eater output
                try:
                    callback(event)
                except Exception as e:
                    self.logger.exception("Eater failed at processing event '%s'" % event)

            except Empty:
                if all(worker.dead for worker in started):
                    break

    def _consume_feed(self, feed, event_queue):
        try:
            feed.consume(event_queue)
        except Exception:
            self.logger.exception("Feed failed while consuming: %s", feed)
