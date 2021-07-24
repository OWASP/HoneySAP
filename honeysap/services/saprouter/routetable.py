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

# External imports
from six import string_types
from six.moves import range
# Custom imports
from honeysap.core.logger import Loggeable
# Optional imports
try:
    import netaddr
except ImportError:
    netaddr = None


class InvalidRouteTableEntry(Exception):
    """The entry in the route table is invalid"""


class RouteTable(Loggeable):
    """A class for storing and handling the route table information.
    """

    # Constants for actions
    ROUTE_ALLOW = 1
    ROUTE_DENY = 2

    # Constants for routing modes
    MODE_ANY = -1
    MODE_RAW = 1
    MODE_NI = 0
    # TODO: Implement route_io mode

    def __init__(self, route_table):
        self.route_table = self.build_table(route_table)

    def parse_route_entry(self, entry):
        """Parses a route table entry.
        """
        # Parse the route as a string
        if isinstance(entry, (string_types, unicode)):
            try:
                action, talk_mode, target, port, password = entry.split(",", 5)
            except ValueError:
                raise InvalidRouteTableEntry
            if password == "":
                password = None
        # Parse the route as a dict
        else:
            try:
                action = entry["action"]
                talk_mode = entry["mode"]
                target = entry["target"]
                port = entry["port"]
                password = entry["password"]
            except KeyError:
                raise InvalidRouteTableEntry

        try:
            action = {"allow": self.ROUTE_ALLOW,
                      "deny": self.ROUTE_DENY}[action.lower()]
            talk_mode = {"any": self.MODE_ANY,
                         "ni": self.MODE_NI,
                         "raw": self.MODE_RAW}[talk_mode.lower()]
        except KeyError:
            raise InvalidRouteTableEntry

        return action, talk_mode, target, port, password

    def parse_target_ports(self, ports):
        """Parses a list of ports"""
        try:
            begin, end = ports.split("-")
        except (AttributeError, ValueError):
            begin, end = ports, ports

        return range(int(begin), int(end) + 1)

    def parse_target_hosts(self, hosts, port):
        """Parses a list of hosts"""
        if netaddr:
            if netaddr.valid_nmap_range(hosts):
                for ip in netaddr.iter_nmap_range(hosts):
                    yield str(ip), port
            else:
                for ip in netaddr.iter_unique_ips(hosts):
                    yield str(ip), port
        else:
            yield hosts, port

    def build_table(self, route_table):
        """Builds an internal structure for performing lookups on the
        route table.
        """
        self.table = {}
        if route_table is None:
            self.logger.debug("Empty route table, denying everything")
            return self.table

        if netaddr is None:
            self.logger.warning("netaddr library not available, not expanding network ranges")

        for entry in route_table:
            # Try to parse the entry
            try:
                action, talk_mode, target, port, password = self.parse_route_entry(entry)
            except InvalidRouteTableEntry:
                continue

            # Expand ports and targets and store the data on the internal table
            for port in self.parse_target_ports(port):
                for (host, port) in self.parse_target_hosts(target, port):
                    self.table[(host, port)] = (action, talk_mode, password)

        self.logger.debug("Using route table: %s" % self.table)

    def lookup_target(self, host, port):
        """Performs a lookup of a target host/port and returns the action to
        perform.
        """

        # If the entry is present, return the info stored there
        if (host, port) in self.table:
            return self.table[(host, port)]

        # Denies the connections by default if no matches on the table
        return self.ROUTE_DENY, self.MODE_ANY, None
