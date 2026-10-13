# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

# Standard imports
import json
import socket
import unittest
from time import monotonic
from unittest.mock import Mock
# External imports
from gevent import socket as gevent_socket
# Custom imports
from honeysap.core.metrics import MetricsReporter, prometheus_text, snapshot


METRICS = {"accepted": 12, "dropped": 1, "queued": 0, "maxsize": 10000, "processed": 11,
           "feed_errors": 0, "active_sessions": 2, "active_campaigns": 1,
           "evicted_sessions": 0, "evicted_campaigns": 0,
           "feeds": {"LogFeed-1": {"id": "LogFeed-1", "delivered": 11, "dropped": 0, "errors": 0,
                                   "skipped": 0, "queued": 0, "disabled_until": None},
                     'Odd"Feed': {"id": 'Odd"Feed', "delivered": 3, "dropped": 2, "errors": 4,
                                  "skipped": 1, "queued": 5, "disabled_until": 0}}}


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class MetricsTest(unittest.TestCase):

    def reporter(self, settings, metrics=None):
        feed = Mock()
        manager = Mock(feeds=[feed])
        manager.metrics.return_value = metrics or METRICS
        reporter = MetricsReporter({"metrics": settings}, manager)
        return reporter, feed

    def test_snapshot_reports_pauses_in_seconds(self):
        metrics = dict(METRICS, feeds={"F": {"disabled_until": monotonic() + 30}})
        values = snapshot(metrics)["feeds"]["F"]
        self.assertEqual(values["paused"], 1)
        self.assertGreater(values["paused_seconds"], 25)
        self.assertNotIn("disabled_until", values)
        self.assertEqual(snapshot(METRICS)["feeds"]["LogFeed-1"]["paused"], 0)

    def test_prometheus_text(self):
        text = prometheus_text(snapshot(METRICS))
        self.assertIn("# TYPE honeysap_events_dropped_total counter\nhoneysap_events_dropped_total 1\n",
                      text)
        self.assertIn('honeysap_feed_delivered_total{feed="LogFeed-1"} 11', text)
        self.assertIn('honeysap_feed_queue_size{feed="Odd\\"Feed"} 5', text)
        self.assertIn('honeysap_feed_delivery_errors_total{feed="Odd\\"Feed"} 4', text)
        names = [line.split()[2] for line in text.splitlines() if line.startswith("# TYPE")]
        self.assertEqual(len(names), len(set(names)))

    def test_report_logs_to_feeds_and_warns_on_drops(self):
        reporter, feed = self.reporter({"interval": 0})
        with self.assertLogs("honeysap.MetricsReporter", "INFO") as logs:
            reporter.report()
            reporter.report()
        feed.log_metrics.assert_called_with(snapshot(METRICS))
        warnings = [line for line in logs.output if line.startswith("WARNING")]
        self.assertEqual(len(warnings), 1)
        self.assertIn("3 events dropped", warnings[0])
        record = [line for line in logs.output if "Metrics {" in line][0]
        self.assertEqual(json.loads(record.split("Metrics ", 1)[1])["accepted"], 12)

    def test_prometheus_endpoint(self):
        port = free_port()
        reporter, _ = self.reporter({"interval": 0, "prometheus": {
            "enabled": True, "listener_address": "127.0.0.1", "listener_port": port}})
        reporter.start()
        try:
            # A gevent socket lets the server run while the test waits
            client = gevent_socket.create_connection(("127.0.0.1", port), timeout=5)
            client.sendall(b"GET /metrics HTTP/1.0\r\nHost: x\r\n\r\n")
            response = b""
            while True:
                data = client.recv(65536)
                if not data:
                    break
                response += data
            client.close()
            self.assertTrue(response.startswith(b"HTTP/1.1 200 OK"))
            self.assertIn(b"Content-Type: text/plain", response)
            self.assertIn(b"honeysap_events_accepted_total 12", response)
        finally:
            reporter.stop()

    def test_interval_is_checked(self):
        with self.assertRaises(ValueError):
            self.reporter({"interval": -1})


if __name__ == "__main__":
    unittest.main()
