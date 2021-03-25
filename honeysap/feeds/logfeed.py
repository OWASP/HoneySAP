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
import logging
# External imports
# Custom imports
from honeysap.core.feed import BaseFeed
from honeysap.core.logger import default_formatter


class LogFeed(BaseFeed):
    """Log file based feed class"""

    EVENT = 9

    @property
    def log_filename(self):
        return self.config.get("log_filename", "honeysap.log")

    def setup(self):
        """Initializes the log file"""
        logging.addLevelName(self.EVENT, "EVENT")

        self.logfile_handler = logging.FileHandler(self.log_filename)
        self.logfile_handler.setFormatter(default_formatter)

        self.feed_logger = logging.getLogger("honeysap.events.logfeed")
        self.feed_logger.setLevel(self.EVENT)
        self.feed_logger.addHandler(self.logfile_handler)

        self.logger.debug("Logging events to filename %s", self.log_filename)
        self.feed_logger.info("Starting log feed")

    def stop(self):
        """Removes the log file handler"""
        self.feed_logger.info("Stopping log feed")
        self.feed_logger.removeHandler(self.logfile_handler)
        self.logger.debug("Closed log filename handler")

    def log(self, event):
        """Logs an event in the log file"""
        self.feed_logger.log(self.EVENT, repr(event))

    def consume(self):
        raise Exception("Log feed can't be consumed")
