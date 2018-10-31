# ===========
# HoneySAP - SAP low-interaction honeypot
#
# Copyright (C) 2015 by Martin Gallo, SecureAuth Corporation
#
# The library was designed and developed by Martin Gallo from
# SecureAuth Corporation's Labs team.
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
import unittest
# External imports

# Custom imports
from honeysap.services.saprouter.routetable import RouteTable


# TODO: Add tests on netaddr network range parsing


class SAPRouterTest(unittest.TestCase):
    pass


class RouteTableTest(unittest.TestCase):

    def test_parse_route_entry(self):
        """Test parsing of route table entries"""

        routetable = RouteTable(None)

        entry = "allow,ni,10.0.0.1,3200-3209,password"
        action, mode, target, port, password = routetable.parse_route_entry(entry)
        self.assertEqual(RouteTable.ROUTE_ALLOW, action)
        self.assertEqual(RouteTable.MODE_NI, mode)
        self.assertEqual("10.0.0.1", target)
        self.assertEqual("3200-3209", port)
        self.assertEqual("password", password)

        entry = "deny,raw,10.0.0.2,3205,"
        action, mode, target, port, password = routetable.parse_route_entry(entry)
        self.assertEqual(RouteTable.ROUTE_DENY, action)
        self.assertEqual(RouteTable.MODE_RAW, mode)
        self.assertEqual("10.0.0.2", target)
        self.assertEqual("3205", port)
        self.assertEqual(None, password)

        entry = "deny,any,10.0.0.2,3205,"
        action, mode, target, port, password = routetable.parse_route_entry(entry)
        self.assertEqual(RouteTable.MODE_ANY, mode)

        entry = {"action": "allow",
                 "mode": "ni",
                 "target": "10.0.0.1",
                 "port": "3200-3209",
                 "password": "password"}
        action, mode, target, port, password = routetable.parse_route_entry(entry)
        self.assertEqual(RouteTable.ROUTE_ALLOW, action)
        self.assertEqual(RouteTable.MODE_NI, mode)
        self.assertEqual("10.0.0.1", target)
        self.assertEqual("3200-3209", port)
        self.assertEqual("password", password)

        entry = {"action": "deny",
                 "mode": "raw",
                 "target": "10.0.0.2",
                 "port": 3205,
                 "password": None}
        action, mode, target, port, password = routetable.parse_route_entry(entry)
        self.assertEqual(RouteTable.ROUTE_DENY, action)
        self.assertEqual(RouteTable.MODE_RAW, mode)
        self.assertEqual("10.0.0.2", target)
        self.assertEqual(3205, port)
        self.assertEqual(None, password)

    def test_build_table(self):
        """Test build table"""

        # Expansion of port ranges
        table = ["allow,ni,10.0.0.1,3200-3209,"]
        routetable = RouteTable(table)

        for port in xrange(3200, 3209):
            self.assertIn(("10.0.0.1", port), routetable.table)
            self.assertEqual((RouteTable.ROUTE_ALLOW,
                              RouteTable.MODE_NI,
                              None), routetable.table[("10.0.0.1", port)])

        # Explicit deny inside an allowed range
        table = ["allow,ni,10.0.0.1,3200-3202,password",
                 "deny,raw,10.0.0.1,3201,"]
        routetable = RouteTable(table)

        self.assertEqual(3, len(routetable.table))
        self.assertIn(("10.0.0.1", 3200), routetable.table)
        self.assertIn(("10.0.0.1", 3201), routetable.table)
        self.assertIn(("10.0.0.1", 3202), routetable.table)
        self.assertEqual((RouteTable.ROUTE_ALLOW,
                          RouteTable.MODE_NI,
                          "password"), routetable.table[("10.0.0.1", 3200)])
        self.assertEqual((RouteTable.ROUTE_DENY,
                          RouteTable.MODE_RAW,
                          None), routetable.table[("10.0.0.1", 3201)])
        self.assertEqual((RouteTable.ROUTE_ALLOW,
                          RouteTable.MODE_NI,
                          "password"), routetable.table[("10.0.0.1", 3202)])

        # Invalid entries
        table = ["accept,ni,10.0.0.1,3200,password",
                 "allow,proto,10.0.0.1,3200,password",
                 "allow,ni,10.0.0.1,3200",
                 {"action": "allow"},
                 {"action": "allow", "mode": "ni"},
                 {"action": "allow", "mode": "ni", "target": "10.0.0.1"},
                 {"action": "allow", "mode": "ni", "target": "10.0.0.1", "port": 3200},
                 {"action": "accept", "mode": "ni", "target": "10.0.0.1", "port": 3200, "password": "password"},
                 {"action": "allow", "mode": "proto", "target": "10.0.0.1", "port": 3200, "password": "password"},
                 ]
        routetable = RouteTable(table)
        self.assertEqual(0, len(routetable.table))

    def test_lookup_target(self):
        """Test look up of a target in the table"""

        # Default deny
        routetable = RouteTable(None)
        action, __, __ = routetable.lookup_target("10.0.0.1", 3200)
        self.assertEqual(RouteTable.ROUTE_DENY, action)

        # Explicit deny inside an allowed range
        table = ["allow,ni,10.0.0.1,3200-3202,password",
                 "deny,raw,10.0.0.1,3201,"]
        routetable = RouteTable(table)

        action, mode, password = routetable.lookup_target("10.0.0.1", 3200)
        self.assertEqual(RouteTable.ROUTE_ALLOW, action)
        self.assertEqual(RouteTable.MODE_NI, mode)
        self.assertEqual("password", password)

        action, mode, password = routetable.lookup_target("10.0.0.1", 3201)
        self.assertEqual(RouteTable.ROUTE_DENY, action)
        self.assertEqual(RouteTable.MODE_RAW, mode)
        self.assertEqual(None, password)

        action, mode, password = routetable.lookup_target("10.0.0.1", 3202)
        self.assertEqual(RouteTable.ROUTE_ALLOW, action)
        self.assertEqual(RouteTable.MODE_NI, mode)
        self.assertEqual("password", password)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(SAPRouterTest))
    suite.addTest(loader.loadTestsFromTestCase(RouteTableTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
