# ===========
# HoneySAP - SAP low-interaction honeypot
#
# Copyright (C) 2015 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security.
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
from uuid import uuid4
# External imports
from gevent.queue import Queue
# Custom imports
from .event import Event
from .logger import Loggeable


class Session(Loggeable):
    """An object representing an attack session
    """

    def __init__(self, event_queue, service, source_ip, source_port, target_ip,
                 target_port):
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
        self.logger_name = "Session_%s_%s:%s_%s:%s" % (service,
                                                       target_ip,
                                                       target_port,
                                                       source_ip,
                                                       source_port)

    def add_event(self, event, **kwargs):
        """Add an event to the attack session."""
        if not isinstance(event, Event):
            event = Event(event, **kwargs)
        event.session = self
        self.logger.debug("Received event %s", event)
        self.event_queue.put(event)


class SessionManager(Loggeable):
    """Object that keeps track of all attack sessions.
    """

    def __init__(self, config):
        """Initialize the attack session."""
        self.config = config
        self.sessions = dict()
        self.event_queue = Queue()
        self.logger.debug("Session manager initialized")

    def get_session(self, service, source_ip, source_port, target_ip,
                    target_port):
        """Obtain an attack session for a given service and a pair of source
        and destination addresses/ports. If the session is not found, it
        creates a new one."""
        key = (service, source_ip, source_port, target_ip, target_port)
        if key not in self.sessions:
            self.sessions[key] = Session(self.event_queue, service, source_ip,
                                         source_port, target_ip, target_port)
            self.logger.debug("Session created for service '%s' on %s:%d client %s:%d",
                              service, target_ip, target_port, source_ip, source_port)
        return self.sessions[key]
