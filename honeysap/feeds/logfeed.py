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
import os
import logging
from logging.handlers import (RotatingFileHandler, TimedRotatingFileHandler,
                              WatchedFileHandler)
# External imports
# Custom imports
from honeysap.core.feed import BaseFeed
from honeysap.core.logger import default_formatter


class LogFeed(BaseFeed):
    """Log file based feed class"""

    supports_consumption = False
    EVENT = 9

    @property
    def log_filename(self):
        return self.config.get("log_filename", "honeysap.log")

    def file_handler(self):
        """Handler for the log file. By default the file is re-opened when
        an external tool (logrotate) renames it; max_bytes or rotate_when
        rotate it here, keeping backup_count files."""
        max_bytes = self.config.get("max_bytes", 0)
        rotate_when = self.config.get("rotate_when")
        backup_count = self.config.get("backup_count", 5)
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        if not isinstance(backup_count, int) or isinstance(backup_count, bool) or backup_count < 0:
            raise ValueError("backup_count must be a non-negative integer")
        if max_bytes and rotate_when:
            raise ValueError("max_bytes and rotate_when cannot be combined")
        if max_bytes:
            return RotatingFileHandler(self.log_filename, maxBytes=max_bytes,
                                       backupCount=backup_count)
        if rotate_when:
            return TimedRotatingFileHandler(self.log_filename, when=rotate_when,
                                            backupCount=backup_count, utc=True)
        return WatchedFileHandler(self.log_filename)

    def setup(self):
        """Initializes the log file"""
        logging.addLevelName(self.EVENT, "EVENT")

        log_dir = os.path.dirname(self.log_filename)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        self.logfile_handler = self.file_handler()
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
        self.logfile_handler.close()
        self.logger.debug("Closed log filename handler")

    def log(self, event):
        """Logs an event in the log file"""
        self.feed_logger.log(self.EVENT, repr(event))

    def log_metrics(self, metrics):
        """Logs a Metrics record next to the events"""
        self.feed_logger.info("Metrics %s", json.dumps(metrics, sort_keys=True))

    def consume(self, queue):
        raise NotImplementedError("Log feed cannot be consumed")
