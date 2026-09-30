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
import re

# External imports
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
    MAX_EXPANDED_ENTRIES = 4096
    # TODO: Implement route_io mode

    def __init__(self, route_table):
        self.route_table = self.build_table(route_table)

    def parse_route_entry(self, entry):
        """Parses a route table entry.
        """
        # Parse the route as a string
        if isinstance(entry, str):
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
        try:
            begin, end = int(begin), int(end)
        except (TypeError, ValueError):
            raise InvalidRouteTableEntry("Invalid port range")
        if not 1 <= begin <= end <= 65535:
            raise InvalidRouteTableEntry("Invalid port range")
        return range(begin, end + 1)

    def parse_target_hosts(self, hosts, port):
        """Parses a list of hosts"""
        matcher = self._host_matcher(hosts)
        for host in self._expanded_hosts(matcher):
            yield host, port

    def _host_matcher(self, hosts):
        """Compile a destination once; large ranges remain bounded matchers."""
        if not isinstance(hosts, str) or not hosts:
            raise InvalidRouteTableEntry("Invalid target host")
        if hosts == "*":
            return None
        if netaddr is None:
            if "*" in hosts or "/" in hosts:
                raise InvalidRouteTableEntry("Network ranges require netaddr")
            return hosts
        try:
            if re.fullmatch(r"[0-9.*-]+", hosts) and ("*" in hosts or "-" in hosts):
                return tuple(netaddr.glob_to_cidrs(hosts))
            if "/" in hosts:
                return (netaddr.IPNetwork(hosts),)
            if netaddr.valid_nmap_range(hosts):
                return (netaddr.IPNetwork(hosts),)
        except (netaddr.AddrFormatError, ValueError) as exc:
            raise InvalidRouteTableEntry("Invalid target range") from exc
        return hosts

    def _expanded_hosts(self, matcher):
        """Expand only small concrete rules for legacy table consumers."""
        if matcher is None:
            return
        if isinstance(matcher, str):
            yield matcher
        else:
            for network in matcher:
                for address in network:
                    yield str(address)

    def _host_matches(self, matcher, host):
        if matcher is None:
            return True
        if isinstance(matcher, str):
            return matcher == host
        try:
            address = netaddr.IPAddress(host)
        except (netaddr.AddrFormatError, ValueError):
            return False
        return any(address in network for network in matcher)

    def build_table(self, route_table):
        """Builds an internal structure for performing lookups on the
        route table.
        """
        self.table = {}
        self.rules = []
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
            try:
                ports = self.parse_target_ports(port)
            except InvalidRouteTableEntry:
                continue
            try:
                matcher = self._host_matcher(target)
            except InvalidRouteTableEntry:
                continue
            result = (action, talk_mode, password)
            self.rules.append((matcher, ports, result))

            if matcher is None:
                host_count = self.MAX_EXPANDED_ENTRIES + 1
            elif isinstance(matcher, str):
                host_count = 1
            else:
                host_count = sum(network.size for network in matcher)
            if host_count * len(ports) <= self.MAX_EXPANDED_ENTRIES:
                for port in ports:
                    for host in self._expanded_hosts(matcher):
                        self.table.setdefault((host, port), result)

        self.logger.debug("Using route table: %s" % self.table)

    def lookup_target(self, host, port):
        """Performs a lookup of a target host/port and returns the action to
        perform.
        """

        for matcher, ports, result in self.rules:
            if port in ports and self._host_matches(matcher, host):
                return result

        # Denies the connections by default if no matches on the table
        return self.ROUTE_DENY, self.MODE_ANY, None
