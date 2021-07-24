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
from threading import Lock
from logging import getLogger, ERROR, WARNING, INFO, DEBUG, Formatter
# External imports
# Custom imports
# Optional imports
try:
    import colorlog
except ImportError:
    colorlog = None


# Lock for avoid issues when creating the loggers
_loggeable_lock = Lock()


# Declare default formatter for logs
default_formatter = Formatter('%(name)s - %(asctime)-15s - %(levelname)-8s - %(message)s')

# Declare colored formatter if the requirement is available
if colorlog:
    colored_formatter = colorlog.ColoredFormatter('%(blue)s%(name)s - %(green)s%(asctime)-15s - %(purple)s%(levelname)-8s - %(log_color)s%(message)s')
else:
    colored_formatter = False


class Loggeable(object):
    """Mixin for attaching a logger to an object. The logger is created in a
    deferred way on first call and available as `logger`. Logger name can be
    customized on an instance base by defining the `logger_name` instance
    attribute.
    """

    @property
    def logger(self):
        """Returns a Python's logging object for this object."""
        if hasattr(self, "_logger") and self._logger.name == self._logger_name:
            return self._logger
        with _loggeable_lock:
            if hasattr(self, "_logger") and self._logger.name == self._logger_name:
                return self._logger

            # We give the change here to the init to set a custom logger name
            if hasattr(self, "logger_name"):
                logger_instance_name = self.logger_name
            else:
                logger_instance_name = self.__class__.__name__

            self._logger_name = "honeysap.%s" % logger_instance_name

            self._logger = getLogger(self._logger_name)
            self._logger.debug("Logger attached to %s", self._logger_name)
            return self._logger

    @classmethod
    def get_level(cls, verbose):
        levels = {0: ERROR,
                  1: WARNING,
                  2: INFO,
                  3: DEBUG}
        if verbose not in levels:
            verbose = 0
        return levels[verbose]
