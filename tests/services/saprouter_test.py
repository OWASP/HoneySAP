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
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
# Custom imports
from honeysap.core.config import Configuration, ConfigurationYAMLParser
from honeysap.services.saprouter.error_profiles import (
    DEFAULT_ERROR_PROFILE_916, TEMPLATE_CONTEXT, render_error_options,
    resolve_error_profile)
from honeysap.services.saprouter.routetable import RouteTable
from honeysap.services.saprouter.saprouter import SAPRouterService


# TODO: Add tests on netaddr network range parsing


class SAPRouterTest(unittest.TestCase):

    def test_916_default_and_legacy_release_profiles(self):
        modern = resolve_error_profile(916)
        self.assertEqual(modern["errors"]["route_denied"]["detail"], "H<1>")
        self.assertEqual(modern["errors"]["admin_info_denied"]["return_code"], -99)
        self.assertTrue(modern["error_count"]["enabled"])
        self.assertEqual(modern["error_count"]["start"], 1)
        self.assertEqual(modern["max_request_length"], 10024)
        self.assertTrue(modern["unknown_packet_error"])

        older = resolve_error_profile("720")
        self.assertEqual(older["fields"]["module"], "nirout.cpp")
        self.assertEqual(older["errors"]["route_denied"]["detail"], "")
        self.assertEqual(older["errors"]["admin_info_denied"]["return_code"], -94)
        self.assertFalse(older["error_count"]["enabled"])
        self.assertIsNone(older["max_request_length"])
        self.assertFalse(older["unknown_packet_error"])

    def test_packet_behavior_profile_overrides_and_normalization(self):
        modern = resolve_error_profile(916, {
            "max_request_length": "64", "unknown_packet_error": False})
        self.assertEqual(modern["max_request_length"], 64)
        self.assertFalse(modern["unknown_packet_error"])
        self.assertEqual(resolve_error_profile(916, {
            "max_request_length": None})["max_request_length"], None)
        self.assertEqual(resolve_error_profile(720, {
            "max_request_length": 128})["max_request_length"], 128)
        self.assertEqual(resolve_error_profile(916)["max_request_length"], 10024)

    def test_partial_overrides_do_not_mutate_version_defaults(self):
        custom = resolve_error_profile(916, {
            "fields": {"component": "Router NI"},
            "error_count": {"start": 10},
            "errors": {"route_denied": {"error": "blocked $target_host"}}
        })
        self.assertEqual(custom["fields"]["component"], "Router NI")
        self.assertEqual(custom["error_count"]["start"], 10)
        self.assertEqual(custom["errors"]["route_denied"]["error"],
                         "blocked $target_host")
        self.assertEqual(DEFAULT_ERROR_PROFILE_916["fields"]["component"],
                         "NI (network interface)")
        self.assertEqual(resolve_error_profile(916)["error_count"]["start"], 1)

    def test_invalid_route_can_override_one_line_or_all_lines(self):
        one = resolve_error_profile(916, {"errors": {"invalid_route": {
            "line_by_reason": {"bad_offset": "908"}}}})
        self.assertEqual(render_error_options(
            one, "invalid_route", TEMPLATE_CONTEXT, "bad_offset")["line"], "908")
        self.assertEqual(render_error_options(
            one, "invalid_route", TEMPLATE_CONTEXT, "no_hops")["line"], "3997")

        all_lines = resolve_error_profile(916, {"errors": {"invalid_route": {
            "line": "same-line"}}})
        self.assertEqual(render_error_options(
            all_lines, "invalid_route", TEMPLATE_CONTEXT, "bad_offset")["line"],
            "same-line")

    def test_invalid_profile_rejected_before_listener_setup(self):
        invalid = ({"errors": {"unknown_case": {"error": "bad"}}},
                   {"errors": {"route_denied": {"error": "$typo"}}},
                   {"errors": {"invalid_route": {
                       "line_by_reason": {"wrong_reason": "7"}}}},
                   {"error_count": {"route_accept_step": -1}},
                   {"errors": {"route_denied": {"count_after": -1}}},
                   {"fields": {"module": {"not": "text"}}},
                   {"max_request_length": -1},
                   {"max_request_length": 0},
                   {"max_request_length": True},
                   {"max_request_length": 1.5},
                   {"max_request_length": "ten"},
                   {"unknown_packet_error": 1})
        for overrides in invalid:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    resolve_error_profile(916, overrides)

        config = Configuration({"error_profile": invalid[1], "virtual": True})
        with patch.object(SAPRouterService, "server_cls") as server_cls:
            with self.assertRaises(ValueError):
                SAPRouterService(config, Mock(), Mock(), Mock())
        server_cls.assert_not_called()

    def test_existing_counter_start_option_takes_precedence(self):
        config = Configuration({"virtual": True, "release": "916",
                                "error_count_start": 3,
                                "error_profile": {"error_count": {"start": 10}}})
        service = SAPRouterService(config, Mock(), Mock(), Mock())
        try:
            self.assertEqual(service.server.error_count, 3)
        finally:
            service.stop()

    def test_standalone_916_yaml_profile_loads(self):
        profile_file = Path(__file__).parents[2] / "profiles" / "saprouter-916.yml"
        config = ConfigurationYAMLParser().parse_file(str(profile_file))
        service = config.config_for("services", "service", "SAPRouterService")[0]
        self.assertEqual(service.get("release"), 916)
        self.assertEqual(service.get("route_table"), [])
        resolved = resolve_error_profile(service.get("release"),
                                         service.get("error_profile"))
        self.assertEqual(resolved, DEFAULT_ERROR_PROFILE_916)


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

        for port in range(3200, 3210):
            self.assertIn(("10.0.0.1", port), routetable.table)
            self.assertEqual((RouteTable.ROUTE_ALLOW,
                              RouteTable.MODE_NI,
                              None), routetable.table[("10.0.0.1", port)])

        # An earlier exact deny takes precedence inside a later allowed range.
        table = ["deny,raw,10.0.0.1,3201,",
                 "allow,ni,10.0.0.1,3200-3202,password"]
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

    def test_invalid_port_ranges_do_not_abort_table_loading(self):
        table = ["allow,ni,10.0.0.1,invalid,",
                 "allow,ni,10.0.0.1,3202-3200,",
                 "allow,ni,10.0.0.1,65536,",
                 "allow,ni,10.0.0.1,3200,"]
        routetable = RouteTable(table)
        self.assertEqual({("10.0.0.1", 3200):
                          (RouteTable.ROUTE_ALLOW, RouteTable.MODE_NI, None)},
                         routetable.table)

    def test_lookup_target(self):
        """Test look up of a target in the table"""

        # Default deny
        routetable = RouteTable(None)
        action, __, __ = routetable.lookup_target("10.0.0.1", 3200)
        self.assertEqual(RouteTable.ROUTE_DENY, action)

        # An earlier exact deny takes precedence inside a later allowed range.
        table = ["deny,raw,10.0.0.1,3201,",
                 "allow,ni,10.0.0.1,3200-3202,password"]
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

        # Reversing the order preserves the earlier permit at the same key.
        routetable = RouteTable(["allow,ni,10.0.0.1,3201,",
                                "deny,raw,10.0.0.1,3201,"])
        self.assertEqual(routetable.lookup_target("10.0.0.1", 3201),
                         (RouteTable.ROUTE_ALLOW, RouteTable.MODE_NI, None))


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(SAPRouterTest))
    suite.addTest(loader.loadTestsFromTestCase(RouteTableTest))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
