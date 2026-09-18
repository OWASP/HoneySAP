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

import unittest
from unittest.mock import patch

import gevent
from gevent.event import Event as GreenletEvent
from gevent.queue import Queue

from honeysap.core.config import Configuration
from honeysap.core.feed import BaseFeed, FeedManager
from honeysap.core.service import ServiceManager
from honeysap.core.session import SessionManager


DEADLINE = 2


class RecordingFeed(BaseFeed):

    def setup(self):
        self.received = Queue()
        self.stop_count = 0

    def log(self, event):
        self.received.put(event)

    def consume(self, queue):
        pass

    def stop(self):
        self.stop_count += 1


class FailingFeed(RecordingFeed):

    def log(self, event):
        raise ValueError("synthetic feed failure")


class FailingStopFeed(RecordingFeed):

    def stop(self):
        super().stop()
        raise ValueError("synthetic stop failure")


class BlockingFeed(RecordingFeed):

    def setup(self):
        super().setup()
        self.logging = GreenletEvent()
        self.released = GreenletEvent()
        self.closed = False

    def log(self, event):
        self.logging.set()
        self.released.wait()
        if self.closed:
            raise AssertionError("feed closed while logging")
        super().log(event)

    def stop(self):
        self.closed = True
        super().stop()


class ConsumingFeed(RecordingFeed):

    def setup(self):
        super().setup()
        self.consuming = GreenletEvent()
        self.released = GreenletEvent()

    def consume(self, queue):
        self.consuming.set()
        self.released.wait()

    def stop(self):
        self.released.set()
        super().stop()


class PublishingFeed(RecordingFeed):

    def consume(self, queue):
        queue.put("first")
        queue.put("second")


class FailingConsumeFeed(RecordingFeed):

    def consume(self, queue):
        raise ValueError("synthetic consume failure")


class SelfStoppingFeed(RecordingFeed):

    def log(self, event):
        self.manager.stop()
        if self.stop_count:
            raise AssertionError("feed closed before log returned")
        super().log(event)


class SelfStoppingConsumerFeed(RecordingFeed):

    def setup(self):
        super().setup()
        self.finished = GreenletEvent()

    def consume(self, queue):
        self.manager.stop()
        gevent.sleep(0)  # Give cleanup a chance to run before returning.
        if self.stop_count:
            raise AssertionError("feed closed before consume returned")
        self.finished.set()


class UnsupportedFeed(RecordingFeed):

    supports_consumption = False

    def consume(self, queue):
        raise AssertionError("unsupported feed was consumed")


class ControlledService:

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.alias = "controlled"
        self.started = GreenletEvent()
        self.released = GreenletEvent()
        self.run_count = 0
        self.stop_count = 0

    def run(self):
        self.run_count += 1
        self.started.set()
        self.released.wait()

    def stop(self):
        self.stop_count += 1
        self.released.set()


class UnkillableWorker:

    dead = False

    def join(self, timeout=None):
        pass

    def kill(self, block=False, timeout=None):
        pass


class CoreConcurrencyTest(unittest.TestCase):

    def make_feed_manager(self):
        config = Configuration()
        sessions = SessionManager(config)
        return sessions, FeedManager(config, sessions)

    def start_feed_worker(self, manager):
        workers = []

        def tracked_spawn(callback, *args):
            worker = gevent.spawn(callback, *args)
            workers.append(worker)
            return worker

        with patch("honeysap.core.feed.spawn", tracked_spawn):
            manager.run()
        self.assertEqual(len(workers), 1)
        return workers[0]

    def stop_feed_worker(self, manager, worker):
        manager.stop()
        worker.join(timeout=DEADLINE)
        self.assertTrue(worker.dead, "feed worker did not terminate")

    def test_feed_failure_does_not_block_delivery_to_other_feeds(self):
        sessions, manager = self.make_feed_manager()
        failing = FailingFeed(Configuration())
        recording = RecordingFeed(Configuration())
        manager.add_feed(failing)
        manager.add_feed(recording)
        worker = self.start_feed_worker(manager)
        try:
            session = sessions.get_session("test", "127.0.0.1", 1,
                                           "127.0.0.1", 2)
            session.add_event("one")
            session.add_event("two")
            received = [recording.received.get(timeout=DEADLINE)
                        for _ in range(2)]
            self.assertEqual([event.event for event in received], ["one", "two"])
            self.assertTrue(all(event.session is session for event in received))
            self.assertTrue(recording.received.empty())
        finally:
            self.stop_feed_worker(manager, worker)
        self.assertEqual(failing.stop_count, 1)
        self.assertEqual(recording.stop_count, 1)

    def test_feed_stop_is_idempotent(self):
        sessions, manager = self.make_feed_manager()
        feed = RecordingFeed(Configuration())
        manager.add_feed(feed)
        worker = self.start_feed_worker(manager)
        self.stop_feed_worker(manager, worker)
        manager.stop()
        self.assertEqual(feed.stop_count, 1)

    def test_repeated_run_and_post_stop_calls_do_not_spawn_workers(self):
        _, manager = self.make_feed_manager()
        feed = ConsumingFeed(Configuration())
        manager.add_feed(feed)
        worker = self.start_feed_worker(manager)
        manager.run()
        self.assertIs(manager.worker, worker)
        self.stop_feed_worker(manager, worker)
        manager.run()
        manager.consume_events(lambda event: None)
        self.assertIs(manager.worker, worker)
        self.assertEqual(manager.consumers, [])
        self.assertFalse(feed.consuming.is_set())

    def test_failing_feed_stop_still_closes_others_and_consumers(self):
        _, manager = self.make_feed_manager()
        failing = FailingStopFeed(Configuration())
        consuming = ConsumingFeed(Configuration())
        manager.add_feed(failing)
        manager.add_feed(consuming)
        main = gevent.spawn(manager.consume_events, lambda event: None)
        try:
            self.assertTrue(consuming.consuming.wait(timeout=DEADLINE))
            with self.assertRaisesRegex(ValueError, "synthetic stop failure"):
                manager.stop()
            main.join(timeout=DEADLINE)
            self.assertTrue(main.dead)
            self.assertTrue(all(worker.dead for worker in manager.consumers))
            self.assertEqual(failing.stop_count, 1)
            self.assertEqual(consuming.stop_count, 1)
            manager.stop()
        finally:
            consuming.released.set()
            if not main.dead:
                main.kill(block=True, timeout=DEADLINE)

    def test_events_from_two_sessions_keep_per_session_order(self):
        sessions, manager = self.make_feed_manager()
        feed = RecordingFeed(Configuration())
        manager.add_feed(feed)
        worker = self.start_feed_worker(manager)
        first = sessions.get_session("first", "127.0.0.1", 1,
                                     "127.0.0.1", 2)
        second = sessions.get_session("second", "127.0.0.1", 3,
                                      "127.0.0.1", 4)

        def produce(session, prefix):
            for index in range(5):
                session.add_event("%s-%d" % (prefix, index))

        producers = [gevent.spawn(produce, first, "first"),
                     gevent.spawn(produce, second, "second")]
        try:
            gevent.joinall(producers, timeout=DEADLINE)
            self.assertTrue(all(producer.dead for producer in producers))
            received = [feed.received.get(timeout=DEADLINE) for _ in range(10)]
            for session, prefix in ((first, "first"), (second, "second")):
                names = [event.event for event in received if event.session is session]
                self.assertEqual(names, ["%s-%d" % (prefix, index)
                                         for index in range(5)])
            self.assertTrue(feed.received.empty())
        finally:
            self.stop_feed_worker(manager, worker)
            for producer in producers:
                if not producer.dead:
                    producer.kill(block=True, timeout=DEADLINE)

    def test_feed_stop_terminates_idle_worker(self):
        _, manager = self.make_feed_manager()
        worker = self.start_feed_worker(manager)
        try:
            gevent.sleep(0)  # Let the worker enter queue.get(), not a timing delay.
            manager.stop()
            worker.join(timeout=DEADLINE)
            self.assertTrue(worker.dead, "stop left the idle worker blocked")
        finally:
            if not worker.dead:
                worker.kill(block=True, timeout=DEADLINE)

    def test_stop_drops_queued_event_before_feed_closes(self):
        sessions, manager = self.make_feed_manager()
        feed = RecordingFeed(Configuration())
        manager.add_feed(feed)
        worker = self.start_feed_worker(manager)
        session = sessions.get_session("test", "127.0.0.1", 1,
                                       "127.0.0.1", 2)
        session.add_event("queued")
        self.stop_feed_worker(manager, worker)
        self.assertTrue(feed.received.empty())
        self.assertEqual(feed.stop_count, 1)

    def test_stop_waits_for_inflight_log_before_closing_feed(self):
        sessions, manager = self.make_feed_manager()
        feed = BlockingFeed(Configuration())
        manager.add_feed(feed)
        worker = self.start_feed_worker(manager)
        session = sessions.get_session("test", "127.0.0.1", 1,
                                       "127.0.0.1", 2)
        session.add_event("inflight")
        self.assertTrue(feed.logging.wait(timeout=DEADLINE))
        stopper = gevent.spawn(manager.stop)
        try:
            gevent.sleep(0)
            self.assertTrue(manager.stopped.is_set())
            self.assertFalse(feed.closed)
            feed.released.set()
            stopper.join(timeout=DEADLINE)
            self.assertTrue(stopper.dead)
            self.assertIsNone(stopper.exception)
            self.assertTrue(worker.dead)
            self.assertEqual(feed.received.get(timeout=DEADLINE).event, "inflight")
            self.assertTrue(feed.closed)
        finally:
            feed.released.set()
            manager.stop()
            if not stopper.dead:
                stopper.kill(block=True, timeout=DEADLINE)
            if not worker.dead:
                worker.kill(block=True, timeout=DEADLINE)

    def test_worker_requested_stop_defers_feed_close_until_log_returns(self):
        sessions, manager = self.make_feed_manager()
        feed = SelfStoppingFeed(Configuration())
        feed.manager = manager
        manager.add_feed(feed)
        worker = self.start_feed_worker(manager)
        session = sessions.get_session("test", "127.0.0.1", 1,
                                       "127.0.0.1", 2)
        session.add_event("self-stop")
        try:
            self.assertEqual(feed.received.get(timeout=DEADLINE).event, "self-stop")
            manager.stop()
            self.assertTrue(worker.dead)
            self.assertTrue(manager.cleanup_worker.dead)
            self.assertEqual(feed.stop_count, 1)
        finally:
            manager.stop()
            if not worker.dead:
                worker.kill(block=True, timeout=DEADLINE)

    def test_consumer_requested_stop_defers_feed_close_until_return(self):
        _, manager = self.make_feed_manager()
        feed = SelfStoppingConsumerFeed(Configuration())
        feed.manager = manager
        manager.add_feed(feed)
        main = gevent.spawn(manager.consume_events, lambda event: None)
        try:
            self.assertTrue(feed.finished.wait(timeout=DEADLINE))
            manager.stop()
            main.join(timeout=DEADLINE)
            self.assertTrue(main.dead)
            self.assertTrue(manager.consumers[0].dead)
            self.assertEqual(feed.stop_count, 1)
        finally:
            manager.stop()
            if not main.dead:
                main.kill(block=True, timeout=DEADLINE)

    def test_stop_bounds_a_stuck_feed_log(self):
        sessions, manager = self.make_feed_manager()
        feed = BlockingFeed(Configuration())
        manager.add_feed(feed)
        worker = self.start_feed_worker(manager)
        session = sessions.get_session("test", "127.0.0.1", 1,
                                       "127.0.0.1", 2)
        session.add_event("stuck")
        try:
            self.assertTrue(feed.logging.wait(timeout=DEADLINE))
            with patch("honeysap.core.feed.WORKER_STOP_TIMEOUT", 0.01):
                manager.stop()
            self.assertTrue(worker.dead)
            self.assertTrue(feed.closed)
            self.assertTrue(feed.received.empty())
        finally:
            feed.released.set()
            if not worker.dead:
                worker.kill(block=True, timeout=DEADLINE)

    def test_stop_does_not_close_feed_if_worker_cannot_be_killed(self):
        _, manager = self.make_feed_manager()
        feed = RecordingFeed(Configuration())
        manager.add_feed(feed)
        manager.worker = UnkillableWorker()
        with self.assertRaisesRegex(RuntimeError, "processing worker did not stop"):
            manager.stop()
        self.assertTrue(manager.stopped.is_set())
        self.assertEqual(feed.stop_count, 0)

    def test_unexpected_cleanup_failure_is_reported(self):
        _, manager = self.make_feed_manager()
        with patch.object(manager, "_finish_stop",
                          side_effect=ValueError("synthetic cleanup failure")):
            with self.assertRaisesRegex(ValueError, "synthetic cleanup failure"):
                manager.stop()
        self.assertTrue(manager.cleanup_worker.dead)

    def test_stop_terminates_feed_consumers(self):
        _, manager = self.make_feed_manager()
        feed = ConsumingFeed(Configuration())
        manager.add_feed(feed)
        main = gevent.spawn(manager.consume_events, lambda event: None)
        try:
            self.assertTrue(feed.consuming.wait(timeout=DEADLINE))
            self.assertEqual(len(manager.consumers), 1)
            manager.stop()
            main.join(timeout=DEADLINE)
            self.assertTrue(main.dead)
            self.assertTrue(manager.consumers[0].dead)
        finally:
            feed.released.set()
            if not main.dead:
                main.kill(block=True, timeout=DEADLINE)

    def test_consumer_callback_failure_does_not_block_next_event(self):
        _, manager = self.make_feed_manager()
        manager.add_feed(UnsupportedFeed(Configuration()))
        manager.add_feed(PublishingFeed(Configuration()))
        received = []
        def callback(event):
            received.append(event)
            if event == "first":
                raise ValueError("synthetic callback failure")
            manager.stop()

        main = gevent.spawn(manager.consume_events, callback)
        try:
            main.join(timeout=DEADLINE)
            self.assertTrue(main.dead)
            self.assertIsNone(main.exception)
            self.assertEqual(received, ["first", "second"])
            self.assertEqual(len(manager.consumers), 1)
            self.assertTrue(manager.consumers[0].dead)
        finally:
            manager.stop()
            if not main.dead:
                main.kill(block=True, timeout=DEADLINE)

    def test_finished_and_failed_consumers_drain_then_return(self):
        _, manager = self.make_feed_manager()
        manager.add_feed(FailingConsumeFeed(Configuration()))
        manager.add_feed(PublishingFeed(Configuration()))
        received = []
        main = gevent.spawn(manager.consume_events, received.append)
        try:
            main.join(timeout=DEADLINE)
            self.assertTrue(main.dead, "consumer loop did not exit after producers")
            self.assertIsNone(main.exception)
            self.assertEqual(received, ["first", "second"])
            self.assertEqual(len(manager.consumers), 2)
            self.assertTrue(all(worker.dead for worker in manager.consumers))
        finally:
            manager.stop()
            if not main.dead:
                main.kill(block=True, timeout=DEADLINE)

    def test_repeated_consumption_does_not_retain_dead_workers(self):
        _, manager = self.make_feed_manager()
        manager.add_feed(PublishingFeed(Configuration()))
        received = []
        try:
            manager.consume_events(received.append)
            first = manager.consumers[0]
            self.assertTrue(first.dead)
            manager.consume_events(received.append)
            self.assertEqual(received, ["first", "second", "first", "second"])
            self.assertEqual(len(manager.consumers), 1)
            self.assertIsNot(manager.consumers[0], first)
        finally:
            manager.stop()

    def test_consume_events_stop_terminates_idle_worker(self):
        _, manager = self.make_feed_manager()
        manager.add_feed(ConsumingFeed(Configuration()))
        worker = gevent.spawn(manager.consume_events, lambda event: None)
        try:
            gevent.sleep(0)
            manager.stop()
            worker.join(timeout=DEADLINE)
            self.assertTrue(worker.dead, "stop left the consumer blocked")
        finally:
            if not worker.dead:
                worker.kill(block=True, timeout=DEADLINE)

    def test_no_consumable_feeds_returns_without_workers(self):
        _, manager = self.make_feed_manager()
        manager.add_feed(UnsupportedFeed(Configuration()))
        manager.consume_events(lambda event: None)
        self.assertEqual(manager.consumers, [])
        manager.stop()

    def test_service_manager_starts_enabled_and_stops_once(self):
        config = Configuration()
        manager = ServiceManager(config, None, SessionManager(config))
        enabled = ControlledService()
        disabled = ControlledService(enabled=False)
        manager.add_service(enabled)
        manager.add_service(disabled)
        def stop_after_start():
            if not enabled.started.wait(timeout=DEADLINE):
                raise AssertionError("enabled service did not start")
            manager.stop()
            manager.stop()

        stopper = gevent.spawn(stop_after_start)
        unrelated_released = GreenletEvent()
        unrelated = gevent.spawn(unrelated_released.wait)
        try:
            # An unrelated worker must not hold up service shutdown.
            with gevent.Timeout(DEADLINE + 1):
                manager.run()
            stopper.join(timeout=DEADLINE)
            self.assertTrue(stopper.dead, "stopper did not complete")
            self.assertIsNone(stopper.exception)
            self.assertFalse(unrelated.dead)
            self.assertTrue(enabled.started.is_set())
            self.assertFalse(disabled.started.is_set())
            self.assertEqual(enabled.run_count, 1)
            self.assertEqual(disabled.run_count, 0)
            self.assertEqual(enabled.stop_count, 1)
            self.assertEqual(disabled.stop_count, 1)
        finally:
            unrelated_released.set()
            unrelated.join(timeout=DEADLINE)
            enabled.released.set()
            disabled.released.set()
            manager.stop()
            if not stopper.dead:
                stopper.kill(block=True, timeout=DEADLINE)
