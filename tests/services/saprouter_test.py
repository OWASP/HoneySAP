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
from types import SimpleNamespace
from unittest.mock import Mock, patch
from scapy.packet import Raw
from pysap.SAPNI import SAPNI, SAPNIStreamSocket
from pysap.SAPMS import SAPMS
from pysap.SAPRouter import SAPRouter, SAPRouterRouteHop
# Custom imports
from honeysap.core.config import Configuration, ConfigurationYAMLParser
from honeysap.services.saprouter.error_profiles import (
    DEFAULT_ERROR_PROFILE_916, TEMPLATE_CONTEXT, render_error_options,
    resolve_error_profile)
from honeysap.services.saprouter.routetable import RouteTable
from honeysap.services.saprouter.saprouter import (SAPRouterService,
                                                  SAPRouterServerHandler)


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



class SAPRouterHandlerTest(unittest.TestCase):

    def test_router_rejects_non_router_packet_without_indexing_it(self):
        handler = self.make_router_handler()
        handler.packet = SAPNI() / Raw(b"invalid")
        handler.handle_data()
        handler.session.add_event.assert_any_call("Invalid SAPRouter packet")
        self.assertEqual(handler.request.send.call_args.args[0].return_code, -93)

    def test_router_profile_packet_size_boundary_closes_without_timeout_error(self):
        handler = self.make_router_handler()
        handler.close = Mock()
        handler.packet = SAPNI() / Raw(b"X" * 10025)
        handler.handle_data()
        handler.close.assert_called_once_with()
        handler.request.send.assert_not_called()

        handler = self.make_router_handler()
        handler.packet = SAPNI() / Raw(b"X" * 10024)
        handler.handle_data()
        response = handler.request.send.call_args.args[0]
        self.assertEqual(response.return_code, -93)
        self.assertEqual(response.err_text_value.line, b"3825")

    def test_router_packet_limit_can_be_overridden_or_disabled(self):
        handler = self.make_router_handler()
        handler.config.update({"error_profile": {"max_request_length": 8}})
        handler.close = Mock()
        handler.packet = SAPNI() / Raw(b"X" * 9)
        handler.handle_data()
        handler.close.assert_called_once_with()
        handler.request.send.assert_not_called()

        handler = self.make_router_handler()
        handler.config.update({"error_profile": {"max_request_length": None}})
        handler.close = Mock()
        handler.packet = SAPNI() / Raw(b"X" * 10025)
        handler.handle_data()
        handler.close.assert_not_called()
        self.assertEqual(handler.request.send.call_args.args[0].return_code, -93)

        handler = self.make_router_handler()
        handler.config.update({"release": 720})
        handler.close = Mock()
        handler.packet = SAPNI() / Raw(b"X" * 10025)
        handler.handle_data()
        handler.close.assert_not_called()
        handler.request.send.assert_not_called()

    def test_router_unknown_packet_reply_is_profile_controlled(self):
        handler = self.make_router_handler()
        handler.config.update({"error_profile": {"unknown_packet_error": False}})
        handler.packet = SAPNI() / Raw(b"invalid")
        handler.handle_data()
        handler.request.send.assert_not_called()

        handler = self.make_router_handler()
        handler.config.update({"release": 720, "error_profile": {
            "unknown_packet_error": True}})
        handler.packet = SAPNI() / Raw(b"invalid")
        handler.handle_data()
        self.assertEqual(handler.request.send.call_args.args[0].return_code, -93)

    def make_router_handler(self):
        handler = SAPRouterServerHandler.__new__(SAPRouterServerHandler)
        handler.config = Configuration({"release": 916, "hostname": "saprouter-lab",
                                        "router_version": 40,
                                        "router_version_patch": 7,
                                        "external_admin": False})
        handler.client_address = ("172.17.0.1", 50000)
        handler.server = SimpleNamespace(route_table=RouteTable(None),
                                         listener_port=3299, error_count=1,
                                         clients={handler.client_address:
                                                  SimpleNamespace(ni_version=None)})
        handler.session = Mock()
        handler.request = Mock()
        return handler

    def test_router_defaults_to_916_error_text_without_release_option(self):
        handler = self.make_router_handler()
        handler.config = Configuration({"hostname": "router.example"})
        handler.deny_route("127.0.0.1", 3200)
        response = handler.request.send.call_args.args[0]
        self.assertEqual(handler.release, 916)
        self.assertEqual(handler.router_version_patch, 7)
        self.assertEqual(response.err_text_value.release, b"916")
        self.assertEqual(response.err_text_value.version, b"40")
        self.assertEqual(response.err_text_value.module, b"")
        self.assertEqual(response.err_text_value.location,
                         b"SAProuter 40.7 on 'router.example'")
        self.assertEqual(response.err_text_value.error_count, b"4")

    def test_router_error_profile_overrides_text_metadata_and_serial(self):
        handler = self.make_router_handler()
        handler.config.update({"error_profile": {
            "fields": {"counter": "7", "component": "Router NI",
                       "location": "Router $release on '$hostname'"},
            "error_time_format": "%Y",
            "partner_name_mode": "loopback",
            "error_count": {"start": 10},
            "errors": {"route_denied": {
                "return_code": -77,
                "error": "blocked $target_host:$target_port for $peer_ip",
                "detail": "custom denial", "module": "access.cpp",
                "line": "77", "count_step": 7, "count_after": 2},
                "invalid_route": {"line_by_reason": {"bad_offset": "908"}}}
        }})
        del handler.server.error_count
        self.assertEqual(handler.partner_name_mode, "loopback")
        handler.deny_route("127.0.0.1", 3200)
        response = handler.request.send.call_args.args[0]
        text = response.err_text_value
        self.assertEqual(response.return_code, -77)
        self.assertEqual(text.error, b"blocked 127.0.0.1:3200 for 172.17.0.1")
        self.assertEqual(text.detail, b"custom denial")
        self.assertEqual(text.module, b"access.cpp")
        self.assertEqual(text.line, b"77")
        self.assertEqual(text.component, b"Router NI")
        self.assertEqual(text.counter, b"7")
        self.assertEqual(text.location, b"Router 916 on 'saprouter-lab'")
        self.assertEqual(len(text.error_time), 4)
        self.assertEqual(text.error_count, b"17")
        self.assertEqual(handler.server.error_count, 19)
        handler.invalid_route("bad_offset")
        self.assertEqual(handler.request.send.call_args.args[0]
                         .err_text_value.line, b"908")

    def test_router_profile_controls_version_and_unknown_opcode_steps(self):
        handler = self.make_router_handler()
        handler.config.update({"error_profile": {
            "error_count": {"version_request_step": 9},
            "errors": {"control_unknown": {"count_step": 4,
                                            "count_after": 6}}
        }})
        handler.handle_control(SAPRouter(type=SAPRouter.SAPROUTER_CONTROL,
                                         version=40, opcode=1))
        self.assertEqual(handler.server.error_count, 10)
        handler.handle_control(SAPRouter(type=SAPRouter.SAPROUTER_CONTROL,
                                         version=40, opcode=3))
        response = handler.request.send.call_args.args[0]
        self.assertEqual(response.err_text_value.error_count, b"14")
        self.assertEqual(handler.server.error_count, 20)

    def test_router_profile_controls_generic_error_step_and_serial_disable(self):
        handler = self.make_router_handler()
        handler.config.update({"error_profile": {"error_count": {
            "start": 10, "default_error_step": 8}}})
        del handler.server.error_count
        handler.return_error(return_code=-1, error="synthetic error")
        response = handler.request.send.call_args.args[0]
        self.assertEqual(response.err_text_value.error_count, b"18")

        handler = self.make_router_handler()
        handler.config.update({"error_profile": {"error_count": {
            "enabled": False}}})
        handler.deny_route("127.0.0.1", 3200)
        response = handler.request.send.call_args.args[0]
        self.assertEqual(response.err_text_value.error_count, b"")
        self.assertEqual(handler.server.error_count, 1)

    def test_router_explicit_older_release_keeps_generic_error_baseline(self):
        handler = self.make_router_handler()
        handler.config = Configuration({"release": "720", "hostname": "router.example"})
        handler.deny_route("127.0.0.1", 3200)
        response = handler.request.send.call_args.args[0]
        self.assertEqual(handler.release, 720)
        self.assertEqual(handler.router_version_patch, 4)
        self.assertEqual(response.err_text_value.release, b"720")
        self.assertEqual(response.err_text_value.module, b"nirout.cpp")
        self.assertEqual(response.err_text_value.detail, b"")
        self.assertEqual(response.err_text_value.error_count, b"")

    def test_router_916_denied_route_decodes_host_and_error_metadata(self):
        handler = self.make_router_handler()
        hops = [SAPRouterRouteHop(hostname="127.0.0.1", port="3299"),
                SAPRouterRouteHop(hostname="127.0.0.1", port="3200")]
        request = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE, route_ni_version=40,
                            route_entries=2, route_rest_nodes=1,
                            route_length=sum(len(bytes(hop)) for hop in hops),
                            route_offset=len(bytes(hops[0])), route_string=hops)
        handler.route_request(SAPRouter(bytes(request)))
        response = handler.request.send.call_args.args[0]
        self.assertEqual(response.return_code, -94)
        self.assertEqual(response.err_text_value.error,
                         b"saprouter-lab: route permission denied "
                         b"(172.17.0.1 to 127.0.0.1, 3200)")
        self.assertEqual(response.err_text_value.detail, b"H<1>")
        self.assertEqual(response.err_text_value.error_count, b"4")
        self.assertEqual(response.err_text_value.module, b"")

    def test_router_916_info_denial_uses_real_error_code(self):
        handler = self.make_router_handler()
        handler.handle_admin(SAPRouter(type=SAPRouter.SAPROUTER_ADMIN,
                                       version=40, adm_command=2))
        response = handler.request.send.call_args.args[0]
        self.assertEqual(response.return_code, -99)
        self.assertEqual(response.err_text_value.error,
                         b"info access denied (172.17.0.1 to localhost, 3299)")
        self.assertEqual(response.err_text_value.error_count, b"3")

    def test_router_916_unknown_control_has_module_line_and_count(self):
        handler = self.make_router_handler()
        handler.handle_control(SAPRouter(type=SAPRouter.SAPROUTER_CONTROL,
                                         version=40, opcode=3))
        response = handler.request.send.call_args.args[0]
        self.assertEqual(response.return_code, -13)
        self.assertEqual(response.err_text_value.module,
                         b"/bas/916_REL/src/base/ni/nibuf.cpp")
        self.assertEqual(response.err_text_value.line, b"2432")
        self.assertEqual(response.err_text_value.error_count, b"3")
        self.assertEqual(handler.server.error_count, 6)

    def test_router_916_error_serial_tracks_observed_exchange_sequence(self):
        handler = self.make_router_handler()
        handler.handle_control(SAPRouter(type=SAPRouter.SAPROUTER_CONTROL,
                                         version=40, opcode=1))
        self.assertEqual(handler.server.error_count, 6)
        hops = [SAPRouterRouteHop(hostname="127.0.0.1", port="3299"),
                SAPRouterRouteHop(hostname="127.0.0.1", port="3201")]
        request = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                            route_ni_version=40, route_entries=2,
                            route_rest_nodes=1,
                            route_length=sum(len(bytes(hop)) for hop in hops),
                            route_offset=len(bytes(hops[0])), route_string=hops)
        handler.route_request(SAPRouter(bytes(request)))
        self.assertEqual(handler.request.send.call_args.args[0]
                         .err_text_value.error_count, b"9")
        handler.handle_admin(SAPRouter(type=SAPRouter.SAPROUTER_ADMIN,
                                       version=40, adm_command=2))
        self.assertEqual(handler.request.send.call_args.args[0]
                         .err_text_value.error_count, b"11")
        handler.handle_control(SAPRouter(type=SAPRouter.SAPROUTER_CONTROL,
                                         version=40, opcode=3))
        self.assertEqual(handler.request.send.call_args.args[0]
                         .err_text_value.error_count, b"13")
        self.assertEqual(handler.server.error_count, 16)

    def test_router_unknown_admin_command_is_denied_without_crashing(self):
        handler = self.make_router_handler()
        handler.handle_admin(SAPRouter(type=SAPRouter.SAPROUTER_ADMIN,
                                       version=40, adm_command=99))
        response = handler.request.send.call_args.args[0]
        self.assertEqual(response.return_code, -94)
        self.assertEqual(response.err_text_value.error,
                         b"Admin from remote denied")

    def test_router_916_invalid_route_metadata_precedes_table_denial(self):
        hops = [SAPRouterRouteHop(hostname="127.0.0.1", port="3299"),
                SAPRouterRouteHop(hostname="127.0.0.1", port="3200")]
        total = sum(len(bytes(hop)) for hop in hops)
        first = len(bytes(hops[0]))
        cases = (("no hops", [], 0, 0, 0, 0, "3997"),
                 ("entries", hops, 1, 1, total, first, "4032"),
                 ("remaining", hops, 2, 2, total, first, "4061"),
                 ("offset", hops, 2, 1, total, 0, "4040"))
        for name, route_hops, entries, rest, length, offset, line in cases:
            with self.subTest(name=name):
                handler = self.make_router_handler()
                request = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                    route_ni_version=40, route_entries=entries,
                                    route_rest_nodes=rest, route_length=length,
                                    route_offset=offset, route_string=route_hops)
                handler.handle_route(request)
                response = handler.request.send.call_args.args[0]
                self.assertEqual(response.return_code, -93)
                self.assertEqual(response.err_text_value.error, b"internal error")
                self.assertEqual(response.err_text_value.detail,
                                 b"NiRRouteRepl: invalid route received")
                self.assertEqual(response.err_text_value.module,
                                 b"/bas/916_REL/src/base/ni/nirout.cpp")
                self.assertEqual(response.err_text_value.line, line.encode())

    def test_router_916_declared_length_errors_precede_entry_and_offset_checks(self):
        cases = (
            ("no route bytes", SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                         route_entries=2, route_rest_nodes=1,
                                         route_length=1, route_offset=3), b"3963"),
            ("extra hop bytes", SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                          route_entries=2, route_rest_nodes=1,
                                          route_length=1, route_offset=0,
                                          route_string=[SAPRouterRouteHop()]), b"4004"),
            ("extra named route bytes", SAPRouter(
                type=SAPRouter.SAPROUTER_ROUTE, route_entries=2,
                route_rest_nodes=1, route_length=1, route_offset=0,
                route_string=[SAPRouterRouteHop(hostname="example.invalid"),
                              SAPRouterRouteHop(hostname="example.invalid")]), b"4004"),
        )
        for name, request, line in cases:
            with self.subTest(name=name):
                handler = self.make_router_handler()
                handler.handle_route(SAPRouter(bytes(request)))
                response = handler.request.send.call_args.args[0]
                self.assertEqual(response.return_code, -93)
                self.assertEqual(response.err_text_value.line, line)

    def test_router_916_empty_unknown_host_old_version_and_invalid_service(self):
        cases = (
            ("empty", [SAPRouterRouteHop(), SAPRouterRouteHop()], 40,
             -90, b"219", b""),
            ("unknown", [SAPRouterRouteHop(hostname="example.invalid"),
                         SAPRouterRouteHop(hostname="example.invalid")], 40,
             -90, b"1890", b"getaddrinfo"),
            ("old version", [SAPRouterRouteHop(hostname="example.invalid"),
                             SAPRouterRouteHop(hostname="example.invalid")], 0,
             -96, b"4180", b""),
            ("invalid service", [SAPRouterRouteHop(hostname="127.0.0.1"),
                                 SAPRouterRouteHop(hostname="127.0.0.1",
                                                   port="not-a-service")], 40,
             -91, b"", b""),
        )
        for name, hops, version, code, line, system_call in cases:
            with self.subTest(name=name):
                handler = self.make_router_handler()
                request = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                    route_ni_version=version, route_entries=2,
                                    route_rest_nodes=1,
                                    route_length=sum(len(bytes(hop)) for hop in hops),
                                    route_offset=len(bytes(hops[0])),
                                    route_string=hops)
                handler.handle_route(SAPRouter(bytes(request)))
                response = handler.request.send.call_args.args[0]
                self.assertEqual(response.return_code, code)
                self.assertEqual(response.err_text_value.line, line)
                self.assertEqual(response.err_text_value.system_call,
                                 system_call)

    def test_router_916_idle_timeout_uses_observed_module_and_line(self):
        handler = self.make_router_handler()
        handler.handle_timeout()
        response = handler.request.send.call_args.args[0]
        self.assertEqual(response.return_code, -5)
        self.assertEqual(response.err_text_value.error, b"connection timed out")
        self.assertEqual(response.err_text_value.detail,
                         b"RTPENDLIST::timeoutPend: no route received within 5s (CONNECTED)")
        self.assertEqual(response.err_text_value.module,
                         b"/bas/916_REL/src/base/ni/nirout.cpp")
        self.assertEqual(response.err_text_value.line, b"8897")

    def test_router_916_allowed_but_unavailable_target_replies(self):
        handler = self.make_router_handler()
        handler.server.route_table = RouteTable([{"action": "allow",
                                                "mode": "ni",
                                                "target": "127.0.0.1",
                                                "port": "3200",
                                                "password": None}])
        handler.server.service_manager = Mock()
        handler.server.service_manager.find_service_by_address.return_value = None
        hops = [SAPRouterRouteHop(hostname="127.0.0.1", port="3299"),
                SAPRouterRouteHop(hostname="127.0.0.1", port="3200")]
        request = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                            route_ni_version=40, route_entries=2,
                            route_rest_nodes=1,
                            route_length=sum(len(bytes(hop)) for hop in hops),
                            route_offset=len(bytes(hops[0])), route_string=hops)
        handler.route_request(SAPRouter(bytes(request)))
        response = handler.request.send.call_args.args[0]
        self.assertEqual(response.return_code, -92)
        self.assertEqual(response.err_text_value.error,
                         b"partner '127.0.0.1:3200' not reached")
        self.assertEqual(response.err_text_value.detail,
                         b"H<1> NiPConnect2: 127.0.0.1:3200")
        self.assertEqual(response.err_text_value.module,
                         b"/bas/916_REL/src/base/ni/nixxi.cpp")
        self.assertEqual(response.err_text_value.line, b"3572")
        self.assertEqual(response.err_text_value.system_call, b"connect")
        self.assertEqual(response.err_text_value.errorno, b"111")
        self.assertEqual(response.err_text_value.errorno_text,
                         b"Connection refused")
        self.assertEqual(response.err_text_value.error_count, b"5")
        handler.server.service_manager.find_service_by_address.assert_called_once_with(
            "127.0.0.1", 3200)
        handler.config.partner_name_mode = "loopback"
        handler.route_request(SAPRouter(bytes(request)))
        self.assertEqual(handler.request.send.call_args.args[0]
                         .err_text_value.error,
                         b"partner 'localhost:3200' not reached")

    def test_router_ni_route_handoff_keeps_framing_and_target_decoder(self):
        handler = self.make_router_handler()
        handler.request = Mock()
        handler.request.timeout = None
        handler.request.max_frame_length = 4096
        target = Mock()
        target.server = SimpleNamespace(base_cls=SAPMS, keep_alive=True)
        client = handler.server.clients[handler.client_address]
        client.talk_mode = 0
        client.target_service = target
        handler.handle_routed()
        stream, address = target.handle_virtual.call_args.args
        self.assertIsInstance(stream, SAPNIStreamSocket)
        self.assertIs(stream.basecls, SAPMS)
        self.assertTrue(stream.keep_alive)
        self.assertEqual(stream.max_frame_length, 4096)
        self.assertEqual(address, handler.client_address)

    def test_router_virtual_ni_clean_close_is_not_a_handler_error(self):
        handler = self.make_router_handler()
        handler.closed = SimpleNamespace(is_set=Mock(return_value=False))
        handler.request.timeout = None
        handler.request.max_frame_length = 4096
        client = handler.server.clients[handler.client_address]
        client.routed = True
        client.talk_mode = 0
        target = Mock()
        target.server = SimpleNamespace(base_cls=SAPMS, keep_alive=True)
        target.handle_virtual.side_effect = EOFError
        client.target_service = target
        handler.handle()
        target.handle_virtual.assert_called_once()
        self.assertFalse(handler._timeout.pending)

        target.handle_virtual.side_effect = ValueError("invalid virtual handler")
        with self.assertRaisesRegex(ValueError, "invalid virtual handler"):
            handler.handle()
        self.assertFalse(handler._timeout.pending)

    def test_router_916_accepted_route_advances_process_serial(self):
        handler = self.make_router_handler()
        handler.server.route_table = RouteTable([{"action": "allow",
                                                "mode": "ni",
                                                "target": "127.0.0.1",
                                                "port": "3600",
                                                "password": None}])
        target = Mock()
        handler.server.service_manager = Mock()
        handler.server.service_manager.find_service_by_address.return_value = target
        handler._timeout = Mock()
        hops = [SAPRouterRouteHop(hostname="127.0.0.1", port="3299"),
                SAPRouterRouteHop(hostname="127.0.0.1", port="3600")]
        request = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                            route_ni_version=40, route_entries=2,
                            route_rest_nodes=1,
                            route_length=sum(len(bytes(hop)) for hop in hops),
                            route_offset=len(bytes(hops[0])), route_string=hops)
        handler.route_request(SAPRouter(bytes(request)))
        response = handler.request.send.call_args.args[0]
        self.assertEqual(response.type, SAPRouter.SAPROUTER_PONG)
        self.assertEqual(handler.server.error_count, 6)
        self.assertIs(handler.server.clients[handler.client_address].target_service,
                      target)
        handler._timeout.cancel.assert_called_once_with()

    def test_router_916_raw_permit_to_closed_partner_pongs_then_closes(self):
        handler = self.make_router_handler()
        handler.server.route_table = RouteTable([{"action": "allow",
                                                "mode": "any",
                                                "target": "127.0.0.1",
                                                "port": "3200",
                                                "password": None}])
        handler.server.service_manager = Mock()
        handler.server.service_manager.find_service_by_address.return_value = None
        handler.close = Mock()
        hops = [SAPRouterRouteHop(hostname="127.0.0.1", port="3299"),
                SAPRouterRouteHop(hostname="127.0.0.1", port="3200")]
        request = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                            route_ni_version=40, route_entries=2,
                            route_talk_mode=RouteTable.MODE_RAW,
                            route_rest_nodes=1,
                            route_length=sum(len(bytes(hop)) for hop in hops),
                            route_offset=len(bytes(hops[0])), route_string=hops)
        handler.route_request(SAPRouter(bytes(request)))
        self.assertEqual(handler.request.send.call_args.args[0].type,
                         SAPRouter.SAPROUTER_PONG)
        handler.close.assert_called_once_with()
        self.assertEqual(handler.server.error_count, 5)

    def test_router_restricted_talk_mode_returns_valid_denial(self):
        handler = self.make_router_handler()
        handler.server.route_table = RouteTable([{"action": "allow",
                                                "mode": "ni",
                                                "target": "127.0.0.1",
                                                "port": "3200",
                                                "password": None}])
        hops = [SAPRouterRouteHop(hostname="127.0.0.1", port="3299"),
                SAPRouterRouteHop(hostname="127.0.0.1", port="3200")]
        request = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                            route_ni_version=40, route_entries=2,
                            route_talk_mode=RouteTable.MODE_RAW,
                            route_rest_nodes=1,
                            route_length=sum(len(bytes(hop)) for hop in hops),
                            route_offset=len(bytes(hops[0])), route_string=hops)
        handler.route_request(SAPRouter(bytes(request)))
        self.assertEqual(handler.request.send.call_args.args[0].return_code, -94)

    def test_router_916_route_password_uses_permission_denial(self):
        for name, route_password, expected_code in (
                ("valid", "labpass", -92),
                ("wrong", "wrong", -94),
                ("missing", None, -94)):
            with self.subTest(name=name):
                handler = self.make_router_handler()
                handler.server.route_table = RouteTable([{"action": "allow",
                                                        "mode": "any",
                                                        "target": "127.0.0.1",
                                                        "port": "3200",
                                                        "password": "labpass"}])
                handler.server.service_manager = Mock()
                handler.server.service_manager.find_service_by_address.return_value = None
                hops = [SAPRouterRouteHop(hostname="127.0.0.1", port="3299"),
                        SAPRouterRouteHop(hostname="127.0.0.1", port="3200",
                                          password=route_password)]
                request = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                                    route_ni_version=40, route_entries=2,
                                    route_rest_nodes=1,
                                    route_length=sum(len(bytes(hop)) for hop in hops),
                                    route_offset=len(bytes(hops[0])), route_string=hops)
                handler.route_request(SAPRouter(bytes(request)))
                response = handler.request.send.call_args.args[0]
                self.assertEqual(response.return_code, expected_code)
                if expected_code == -94:
                    self.assertEqual(response.err_text_value.error,
                                     b"saprouter-lab: route permission denied "
                                     b"(172.17.0.1 to 127.0.0.1, 3200)")
                    self.assertEqual(response.err_text_value.detail, b"H<1>")
                    self.assertEqual(response.err_text_value.error_count, b"4")
                    handler.server.service_manager.find_service_by_address.assert_not_called()

def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(SAPRouterTest))
    suite.addTest(loader.loadTestsFromTestCase(RouteTableTest))
    suite.addTest(loader.loadTestsFromTestCase(SAPRouterHandlerTest))
    return suite


test_suite.__test__ = False


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
