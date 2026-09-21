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
from copy import deepcopy
from time import monotonic
from uuid import uuid4
# External imports
from gevent.queue import Full, Queue
# Custom imports
from .event import Event
from .logger import Loggeable


class Session(Loggeable):
    """An object representing an attack session
    """

    def __init__(self, event_queue, service, source_ip, source_port, target_ip,
                 target_port, campaign_uuid=None, enqueue=None,
                 parent_session_uuid=None):
        """Initialize the attack session.
        """
        super(Session, self).__init__()
        self.uuid = uuid4()
        self.event_queue = event_queue
        self.service = service
        self.source_ip = source_ip
        self.source_port = source_port
        self.target_ip = target_ip
        self.target_port = target_port
        self.campaign_uuid = campaign_uuid or uuid4()
        self.parent_session_uuid = parent_session_uuid
        self.enqueue = enqueue
        self.sequence = 0
        self.created_at = monotonic()
        self.last_activity = self.created_at
        self.logger_name = "Session_%s_%s:%s_%s:%s" % (service,
                                                       target_ip,
                                                       target_port,
                                                       source_ip,
                                                       source_port)

    def add_event(self, event, **kwargs):
        """Add an event to the attack session."""
        if not isinstance(event, Event):
            event = Event(event, **kwargs)
        elif event.session is not None:
            # Reuse creates a separate queued event, even for the same session.
            original = event
            event = Event(original.event, data=deepcopy(original.data),
                          request=original.request, response=original.response)
            event.timestamp = original.timestamp
        event.session = self
        self.sequence += 1
        event.sequence = self.sequence
        self.last_activity = monotonic()
        self.logger.debug("Received event %s", event)
        if self.enqueue is not None:
            return self.enqueue(event)
        self.event_queue.put(event)
        return True


class SessionManager(Loggeable):
    """Object that keeps track of all attack sessions.
    """

    def __init__(self, config):
        """Initialize the attack session."""
        self.config = config
        self.sessions = dict()
        self.event_queue_maxsize = self._queue_maxsize()
        self.event_queue = Queue(maxsize=self.event_queue_maxsize)
        self.max_sessions = self._positive_integer("max_sessions", 10000)
        self.max_campaigns = self._positive_integer("max_campaigns", 10000)
        self.session_ttl_seconds = self._positive_number(
            "session_ttl_seconds", 3600, allow_zero=False)
        self.campaign_window_seconds = self._positive_number(
            "campaign_window_seconds", 3600, allow_zero=True)
        self.campaigns = {}
        self.accepted_events = 0
        self.dropped_events = 0
        self.evicted_sessions = 0
        self.evicted_campaigns = 0
        self.logger.debug("Session manager initialized")

    def get_session(self, service, source_ip, source_port, target_ip,
                    target_port, campaign_uuid=None, parent_session_uuid=None):
        """Obtain an attack session for a given service and a pair of source
        and destination addresses/ports. If the session is not found, it
        creates a new one."""
        self.expire_sessions()
        key = (service, source_ip, source_port, target_ip, target_port)
        if key not in self.sessions:
            self._evict_sessions_if_needed()
            campaign_uuid = campaign_uuid or self._campaign_for(source_ip)
            self.sessions[key] = Session(self.event_queue, service, source_ip,
                                         source_port, target_ip, target_port,
                                         campaign_uuid=campaign_uuid,
                                         enqueue=self.enqueue_event,
                                         parent_session_uuid=parent_session_uuid)
            self.logger.debug("Session created for service '%s' on %s:%d client %s:%d",
                              service, target_ip, target_port, source_ip, source_port)
        session = self.sessions[key]
        session.last_activity = monotonic()
        return session

    def _positive_number(self, name, default, allow_zero):
        value = self.config.get(name, default)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValueError("%s must be a number" % name)
        if value < 0 or (not allow_zero and value == 0):
            raise ValueError("%s must be positive%s" %
                             (name, " or zero" if allow_zero else ""))
        return value

    def _queue_maxsize(self):
        return self._positive_integer("event_queue_maxsize", 10000)

    def _positive_integer(self, name, default):
        value = self.config.get(name, default)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("%s must be a positive integer" % name)
        return value

    def _evict_sessions_if_needed(self):
        if len(self.sessions) < self.max_sessions:
            return
        key = min(self.sessions, key=lambda item: self.sessions[item].last_activity)
        del self.sessions[key]
        self.evicted_sessions += 1

    def _campaign_for(self, source_ip):
        if self.campaign_window_seconds == 0:
            return uuid4()
        now = monotonic()
        campaign = self.campaigns.get(source_ip)
        if campaign is None or now - campaign[1] > self.campaign_window_seconds:
            if campaign is None:
                self._evict_campaigns_if_needed()
            campaign = (uuid4(), now)
        self.campaigns[source_ip] = (campaign[0], now)
        return campaign[0]

    def _evict_campaigns_if_needed(self):
        if len(self.campaigns) < self.max_campaigns:
            return
        source_ip = min(self.campaigns, key=lambda item: self.campaigns[item][1])
        del self.campaigns[source_ip]
        self.evicted_campaigns += 1

    def expire_sessions(self):
        """Remove inactive connection sessions and expired campaign entries."""
        now = monotonic()
        expired = [key for key, session in self.sessions.items()
                   if now - session.last_activity > self.session_ttl_seconds]
        for key in expired:
            del self.sessions[key]
        if self.campaign_window_seconds:
            self.campaigns = {
                source_ip: campaign for source_ip, campaign in self.campaigns.items()
                if now - campaign[1] <= self.campaign_window_seconds}
        return len(expired)

    def enqueue_event(self, event):
        """Queue an event without allowing slow feeds to block a listener."""
        try:
            self.event_queue.put_nowait(event)
        except Full:
            self.dropped_events += 1
            self.logger.warning("Event queue full; dropped event '%s'", event.event)
            return False
        self.accepted_events += 1
        return True

    def event_queue_metrics(self):
        return {"accepted": self.accepted_events,
                "dropped": self.dropped_events,
                "queued": self.event_queue.qsize(),
                "maxsize": self.event_queue_maxsize,
                "active_sessions": len(self.sessions),
                "active_campaigns": len(self.campaigns),
                "evicted_sessions": self.evicted_sessions,
                "evicted_campaigns": self.evicted_campaigns}
