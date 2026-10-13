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

"""Internal counters made visible: periodic Metrics log records and an
optional Prometheus endpoint."""

# Standard imports
import json
from time import monotonic
# External imports
from gevent import sleep, spawn
from gevent.pywsgi import WSGIServer
# Custom imports
from honeysap.core.logger import Loggeable


# (metric name, type, help, key in the metrics)
GLOBAL_METRICS = [
    ("honeysap_events_accepted_total", "counter", "Events accepted into the event queue",
     "accepted"),
    ("honeysap_events_dropped_total", "counter", "Events dropped because the event queue was full",
     "dropped"),
    ("honeysap_event_queue_size", "gauge", "Events waiting in the event queue", "queued"),
    ("honeysap_event_queue_maxsize", "gauge", "Capacity of the event queue", "maxsize"),
    ("honeysap_events_processed_total", "counter", "Events handed to the feeds", "processed"),
    ("honeysap_feed_errors_total", "counter", "Feed delivery errors", "feed_errors"),
    ("honeysap_sessions_active", "gauge", "Retained sessions", "active_sessions"),
    ("honeysap_campaigns_active", "gauge", "Retained campaigns", "active_campaigns"),
    ("honeysap_sessions_evicted_total", "counter", "Sessions evicted at max_sessions",
     "evicted_sessions"),
    ("honeysap_campaigns_evicted_total", "counter", "Campaigns evicted at max_campaigns",
     "evicted_campaigns"),
]
FEED_METRICS = [
    ("honeysap_feed_delivered_total", "counter", "Events delivered to the feed", "delivered"),
    ("honeysap_feed_dropped_total", "counter", "Events dropped because the feed queue was full",
     "dropped"),
    ("honeysap_feed_delivery_errors_total", "counter", "Delivery errors of the feed", "errors"),
    ("honeysap_feed_skipped_total", "counter", "Events skipped while the feed was paused",
     "skipped"),
    ("honeysap_feed_queue_size", "gauge", "Events waiting in the feed queue", "queued"),
    ("honeysap_feed_paused", "gauge", "1 while the feed is paused after failures", "paused"),
]


def snapshot(metrics):
    """Metrics with the feed pauses as remaining seconds"""
    now = monotonic()
    result = dict(metrics)
    feeds = {}
    for feed_id, values in metrics.get("feeds", {}).items():
        values = dict(values)
        until = values.pop("disabled_until", None)
        values["paused_seconds"] = round(until - now, 1) if until is not None and until > now \
            else 0
        values["paused"] = 1 if values["paused_seconds"] else 0
        feeds[feed_id] = values
    result["feeds"] = feeds
    return result


def _label(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def prometheus_text(metrics):
    """Metrics in the Prometheus text exposition format"""
    lines = []
    for name, kind, text, key in GLOBAL_METRICS:
        lines += ["# HELP %s %s" % (name, text), "# TYPE %s %s" % (name, kind),
                  "%s %s" % (name, metrics.get(key, 0))]
    feeds = metrics.get("feeds", {})
    for name, kind, text, key in FEED_METRICS:
        lines += ["# HELP %s %s" % (name, text), "# TYPE %s %s" % (name, kind)]
        lines += ['%s{feed="%s"} %s' % (name, _label(feed_id), values.get(key, 0))
                  for feed_id, values in sorted(feeds.items())]
    return "\n".join(lines) + "\n"


class MetricsReporter(Loggeable):
    """Logs the metrics every interval seconds and serves them to
    Prometheus when enabled"""

    def __init__(self, config, feed_manager):
        settings = config.get("metrics") or {}
        self.interval = settings.get("interval", 300)
        if not isinstance(self.interval, (int, float)) or isinstance(self.interval, bool) or \
                self.interval < 0:
            raise ValueError("metrics.interval must be a non-negative number")
        self.prometheus = settings.get("prometheus") or {}
        self.feed_manager = feed_manager
        self.worker = None
        self.server = None
        self.last_dropped = 0

    def metrics(self):
        return snapshot(self.feed_manager.metrics())

    def report(self):
        """One Metrics log record; a warning when events were dropped since
        the last one"""
        metrics = self.metrics()
        self.logger.info("Metrics %s", json.dumps(metrics, sort_keys=True))
        for feed in self.feed_manager.feeds:
            try:
                feed.log_metrics(metrics)
            except Exception:
                self.logger.exception("Feed failed to log metrics: %s", feed)
        feed_drops = sum(values.get("dropped", 0) for values in metrics["feeds"].values())
        dropped = metrics.get("dropped", 0) + feed_drops
        if dropped > self.last_dropped:
            self.logger.warning("%d events dropped since the last metrics report",
                                dropped - self.last_dropped)
        self.last_dropped = dropped
        return metrics

    def run(self):
        while True:
            sleep(self.interval)
            try:
                self.report()
            except Exception:
                self.logger.exception("Metrics report failed")

    def application(self, environ, start_response):
        if environ.get("PATH_INFO") != "/metrics":
            start_response("404 Not Found", [("Content-Type", "text/plain")])
            return [b"Not Found\n"]
        body = prometheus_text(self.metrics()).encode("utf-8")
        start_response("200 OK", [("Content-Type", "text/plain; version=0.0.4; charset=utf-8"),
                                  ("Content-Length", str(len(body)))])
        return [body]

    def start(self):
        if self.interval:
            self.worker = spawn(self.run)
        if self.prometheus.get("enabled"):
            address = (self.prometheus.get("listener_address", "127.0.0.1"),
                       self.prometheus.get("listener_port", 9180))
            self.server = WSGIServer(address, self.application, log=None, error_log=None)
            self.server.start()
            self.logger.info("Serving metrics on http://%s:%d/metrics", *address)

    def stop(self):
        """Stop reporting; the last metrics are logged"""
        try:
            self.report()
        except Exception:
            self.logger.exception("Metrics report failed")
        if self.worker is not None:
            self.worker.kill(block=False)
        if self.server is not None:
            self.server.stop()
