# HoneySAP - SAP low-interaction honeypot
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
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
#   Martin Gallo (@martingalloar) from SecureAuth's Innovation Labs team.
#

# Standard imports
import json
from base64 import b64encode
from datetime import datetime
# External imports

# Custom imports


class Event(object):
    """An object representing an attack session event"""

    def __init__(self, event, data=None, request=None, response=None,
                 session=None):
        self.event = event
        self.data = data
        self.request = request
        self.response = response
        self.session = session
        self.timestamp = datetime.now()

    def __str__(self):
        if self.session is None:
            raise Exception("Event not attached to a session")
        return "<Event '%s' at %s in session '%s'>" % (self.event, self.timestamp, self.session.uuid)

    def __repr__(self):
        if self.session is None:
            raise Exception("Event not attached to a session")
        return json.dumps({"session": str(self.session.uuid),
                           "event": self.event,
                           "data": self.data if self.data else "",
                           "request": b64encode(self.request) if self.request else "",
                           "response": b64encode(self.response) if self.response else "",
                           "service": self.session.service,
                           "source_ip": self.session.source_ip,
                           "source_port": self.session.source_port,
                           "target_ip": self.session.target_ip,
                           "target_port": self.session.target_port,
                           "timestamp": str(self.timestamp)})
