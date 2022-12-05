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
from optparse import OptionGroup
# External imports
from gevent.monkey import patch_all; patch_all()  # @IgnorePep8
# Custom imports
from .feed import FeedManager
from .session import SessionManager
from .config import ConfigurationParserFromFile
from .logger import (Loggeable, default_formatter, colored_formatter)


class HoneySAPEater(Loggeable):

    default_config = "honeysapeater.yml"

    def main(self, argv=None):
        """Main function to run the program"""
        self.argv = argv
        self.get_configuration()
        self.setup()
        self.run()

    def setup(self):
        """Setup all the required objects and managers"""
        self.setup_logger()
        self.setup_feeds()
        self.setup_output()

    def get_configuration(self):
        """Pase configuration from command line and configuration file """
        parser = ConfigurationParserFromFile(default_config=self.default_config)

        logging_group = OptionGroup(parser, "Logging")
        logging_group.add_option("-v", "--verbose", dest="verbose",
                                 action="count", default=0,
                                 help="set verbosity level [default: %default]")
        logging_group.add_option("--colored-console", dest="colored_console",
                                 action="store_true", default=False,
                                 help="set colored console [default: %default]")
        logging_group.add_option("--show-all-logs", dest="verbose_all",
                                 action="store_true", default=False,
                                 help="if the console should print logs for all namespaces (root logger) [default: %default]")
        parser.add_option_group(logging_group)

        self.config, __ = parser.parse_args(self.argv)

    def setup_logger(self):
        """Setup logging options, adding the configured handlers (console and
        log file)."""
        level = Loggeable.get_level(self.config.verbose)

        if self.config.verbose_all:
            namespace = None
        else:
            namespace = 'honeysap'

        if self.config.colored_console and colored_formatter:
            formatter = colored_formatter
        else:
            formatter = default_formatter

        logger = logging.getLogger(namespace)
        logger.level = level
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(level)
        logger.addHandler(stream_handler)

        self.logger.debug("Logging configured")
        self.logger.info("Using config: %s", self.config)

    def setup_feeds(self):
        """Setup attack session feeds configured."""
        self.logger.info("Setting up feeds")
        self.feed_manager = FeedManager(self.config, SessionManager(self.config))
        self.feed_manager.load_feeds()

    def setup_output(self):
        """Setup the output files for writing events."""
        self.logger.info("Setting the output")

        self.outputs = []
        for eater_type in self.config.get("eater_output", ["stdout"]):
            if eater_type == "stdout":
                self.outputs.append(sys.stdout)
            elif eater_type == "file":
                filename = self.config.get("eater_filename", "honeysapeater.log")
                with open(filename, "a") as fd:
                    self.outputs.append(fd)

    def run(self):
        """Launch the configured and enabled services"""

        self.logger.info("Starting consuming feeds")
        try:
            self.feed_manager.consume_events(self.output)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stop all running services and feeds"""
        self.feed_manager.stop()
        for output in self.outputs:
            output.close()

    def output(self, event):
        """Output an event according to the outputs defined for the eater. Each
        output is a file-like object."""
        for output in self.outputs:
            output.write(str(event))
            output.write("\n")
            output.flush()
