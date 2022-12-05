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
import sys
import logging
# External imports
# Custom imports
from honeysap.core.feed import BaseFeed
from honeysap.core.logger import default_formatter, colored_formatter


class ConsoleFeed(BaseFeed):
    """Console based feed class"""

    EVENT = 9

    def setup(self):
        """Initializes the console stream"""
        logging.addLevelName(self.EVENT, "EVENT")

        if self.config.colored_console and colored_formatter:
            formatter = colored_formatter
        else:
            formatter = default_formatter
        self.stream_handler = logging.StreamHandler(sys.stdout)
        self.stream_handler.setFormatter(formatter)

        self.feed_logger = logging.getLogger("honeysap.events.console")
        self.feed_logger.setLevel(self.EVENT)
        self.feed_logger.addHandler(self.stream_handler)

        self.logger.debug("Logging events to console")
        self.feed_logger.info("Starting console feed")

    def stop(self):
        """Removes the log file handler"""
        self.feed_logger.info("Stopping console feed")
        self.feed_logger.removeHandler(self.stream_handler)
        self.logger.debug("Closed log console handler")

    def log(self, event):
        """Logs an event in the log file"""
        self.feed_logger.log(self.EVENT, repr(event))

    def consume(self):
        raise Exception("Console feed can't be consumed")
