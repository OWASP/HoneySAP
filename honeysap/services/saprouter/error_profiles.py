# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

"""Version-specific SAPRouter error replies and profile overrides."""

from copy import deepcopy
from string import Template

from pysap.SAPRouter import SAPRouterError


ERROR_TEXT_FIELDS = {field.name for field in SAPRouterError.fields_desc}
ROUTE_FAILURES = {"no_hops", "missing_route_bytes", "bad_length",
                  "bad_entries", "bad_offset", "bad_rest"}
CASE_FIELDS = ERROR_TEXT_FIELDS | {"count_step", "count_after"}
TEMPLATE_CONTEXT = {
    "hostname": "host.example",
    "release": "916",
    "router_version": "40",
    "router_version_patch": "7",
    "peer_ip": "127.0.0.1",
    "target_host": "127.0.0.1",
    "target_port": "3200",
    "partner_host": "127.0.0.1",
    "listener_port": "3299",
    "opcode": "3",
    "timeout": "5",
    "route_ni_version": "0",
}


DEFAULT_ERROR_PROFILE_916 = {
    "fields": {
        "counter": "1",
        "component": "NI (network interface)",
        "release": "$release",
        "version": "$router_version",
        "module": "",
        "location": "SAProuter $router_version.$router_version_patch on '$hostname'",
    },
    "error_time_format": SAPRouterError.time_format,
    "partner_name_mode": "literal",
    "max_request_length": 10024,
    "unknown_packet_error": True,
    "error_count": {
        "enabled": True,
        "start": 1,
        "default_error_step": 2,
        "version_request_step": 5,
        "route_accept_step": 5,
        "raw_unreachable_step": 4,
    },
    "errors": {
        "invalid_route": {
            "return_code": -93,
            "error": "internal error",
            "detail": "NiRRouteRepl: invalid route received",
            "module": "/bas/916_REL/src/base/ni/nirout.cpp",
            "line_by_reason": {"no_hops": "3997", "missing_route_bytes": "3963",
                               "bad_length": "4004", "bad_entries": "4032",
                               "bad_offset": "4040", "bad_rest": "4061"},
            "count_step": 2,
        },
        "route_version_old": {
            "return_code": -96,
            "error": "invalid client version",
            "detail": "NiRExRouteCon: version $route_ni_version too old",
            "module": "/bas/916_REL/src/base/ni/nirout.cpp",
            "line": "4180",
            "count_step": 2,
        },
        "host_empty": {
            "return_code": -90,
            "error": "hostname '' unknown",
            "detail": "NiHL6GetNodeAddr: hostname empty",
            "module": "/bas/916_REL/src/base/ni/nixxhl6.cpp",
            "line": "219",
            "count_step": 2,
        },
        "host_unknown": {
            "return_code": -90,
            "error": "hostname '$target_host' unknown",
            "detail": "NiPGetHostByName: '$target_host' not found",
            "module": "niuxi.c",
            "line": "1890",
            "system_call": "getaddrinfo",
            "count_step": 2,
        },
        "service_invalid": {
            "return_code": -91,
            "error": "service '$target_port' unknown",
            "count_step": 2,
        },
        "route_expected": {
            "return_code": -93,
            "error": "internal error",
            "detail": "NiRClientHandle: route expected",
            "module": "/bas/916_REL/src/base/ni/nirout.cpp",
            "line": "3825",
            "count_step": 2,
        },
        "route_denied": {
            "return_code": -94,
            "error": "$hostname: route permission denied "
                     "($peer_ip to $target_host, $target_port)",
            "detail": "H<1>",
            "count_step": 3,
        },
        "partner_unreachable": {
            "return_code": -92,
            "error": "partner '$partner_host:$target_port' not reached",
            "detail": "H<1> NiPConnect2: $target_host:$target_port",
            "module": "/bas/916_REL/src/base/ni/nixxi.cpp",
            "line": "3572",
            "system_call": "connect",
            "errorno": "111",
            "errorno_text": "Connection refused",
            "count_step": 4,
        },
        "control_unknown": {
            "return_code": -13,
            "error": "invalid client version",
            "detail": "NiBufIProcMsg: unknown opcode $opcode received",
            "module": "/bas/916_REL/src/base/ni/nibuf.cpp",
            "line": "2432",
            "count_step": 2,
            "count_after": 3,
        },
        "admin_info_denied": {
            "return_code": -99,
            "error": "info access denied ($peer_ip to localhost, $listener_port)",
            "count_step": 2,
        },
        "admin_denied": {
            "return_code": -94,
            "error": "Admin from remote denied",
            "count_step": 2,
        },
        "admin_password_denied": {
            "return_code": -94,
            "error": "route denied",
            "count_step": 2,
        },
        "timeout": {
            "return_code": -5,
            "error": "connection timed out",
            "detail": "RTPENDLIST::timeoutPend: no route received "
                      "within ${timeout}s (CONNECTED)",
            "module": "/bas/916_REL/src/base/ni/nirout.cpp",
            "line": "8897",
            "count_step": 2,
        },
    },
}


DEFAULT_ERROR_PROFILE_LEGACY = deepcopy(DEFAULT_ERROR_PROFILE_916)
DEFAULT_ERROR_PROFILE_LEGACY["fields"]["module"] = "nirout.cpp"
DEFAULT_ERROR_PROFILE_LEGACY["partner_name_mode"] = "loopback"
DEFAULT_ERROR_PROFILE_LEGACY["max_request_length"] = None
DEFAULT_ERROR_PROFILE_LEGACY["unknown_packet_error"] = False
DEFAULT_ERROR_PROFILE_LEGACY["error_count"]["enabled"] = False
DEFAULT_ERROR_PROFILE_LEGACY["errors"]["invalid_route"].pop("module")
DEFAULT_ERROR_PROFILE_LEGACY["errors"]["invalid_route"]["line_by_reason"] = {
    reason: "" for reason in ROUTE_FAILURES}
for case in ("route_version_old", "host_empty", "host_unknown",
             "service_invalid", "route_expected"):
    DEFAULT_ERROR_PROFILE_LEGACY["errors"][case].pop("module", None)
    DEFAULT_ERROR_PROFILE_LEGACY["errors"][case].pop("line", None)
DEFAULT_ERROR_PROFILE_LEGACY["errors"]["route_denied"]["detail"] = ""
DEFAULT_ERROR_PROFILE_LEGACY["errors"]["partner_unreachable"].update(
    detail="", line="", system_call="", errorno="",
    errorno_text="")
DEFAULT_ERROR_PROFILE_LEGACY["errors"]["partner_unreachable"].pop("module")
DEFAULT_ERROR_PROFILE_LEGACY["errors"]["control_unknown"].update(
    line="")
DEFAULT_ERROR_PROFILE_LEGACY["errors"]["control_unknown"].pop("module")
DEFAULT_ERROR_PROFILE_LEGACY["errors"]["admin_info_denied"] = deepcopy(
    DEFAULT_ERROR_PROFILE_LEGACY["errors"]["admin_denied"])
DEFAULT_ERROR_PROFILE_LEGACY["errors"]["timeout"].update(line="")
DEFAULT_ERROR_PROFILE_LEGACY["errors"]["timeout"].pop("module")


def _merge_profile(base, overrides, path="error_profile"):
    """Merge a partial service profile, rejecting unsupported case names."""
    if not isinstance(overrides, dict):
        raise ValueError("%s must be a mapping" % path)
    for key, value in overrides.items():
        if key not in base:
            if path == "error_profile.fields" and key in ERROR_TEXT_FIELDS:
                base[key] = value
                continue
            if path.startswith("error_profile.errors.") and key in CASE_FIELDS:
                base[key] = value
                continue
            raise ValueError("Unknown %s key: %s" % (path, key))
        if isinstance(base[key], dict):
            _merge_profile(base[key], value, "%s.%s" % (path, key))
        else:
            base[key] = value


def _validate_profile(profile):
    limit = profile["max_request_length"]
    if limit is not None:
        if isinstance(limit, bool) or not (
                isinstance(limit, int) or
                isinstance(limit, str) and limit.isdecimal()):
            raise ValueError("error_profile.max_request_length must be a positive integer or null")
        limit = int(limit)
        if limit <= 0:
            raise ValueError("error_profile.max_request_length must be a positive integer or null")
        profile["max_request_length"] = limit
    if not isinstance(profile["unknown_packet_error"], bool):
        raise ValueError("error_profile.unknown_packet_error must be boolean")
    fields = profile["fields"]
    for case, options in profile["errors"].items():
        for key in options:
            if key not in CASE_FIELDS | {"line_by_reason"}:
                raise ValueError("Unknown error_profile.errors.%s key: %s" %
                                 (case, key))
        if "line_by_reason" in options and case != "invalid_route":
            raise ValueError("line_by_reason is only valid for invalid_route")
        lines = options.get("line_by_reason", {})
        if not isinstance(lines, dict):
            raise ValueError("line_by_reason must be a mapping")
        for reason in lines:
            if reason not in ROUTE_FAILURES:
                raise ValueError("Unknown route failure: %s" % reason)
    for values in [fields] + list(profile["errors"].values()):
        for key, value in values.items():
            if key == "line_by_reason":
                strings = value.values()
            elif key in {"return_code", "count_step", "count_after"}:
                try:
                    number = int(value)
                except (TypeError, ValueError) as exc:
                    raise ValueError("Invalid SAPRouter numeric profile value: %s" %
                                     key) from exc
                if key in {"count_step", "count_after"} and number < 0:
                    raise ValueError("SAPRouter error count step must be nonnegative")
                continue
            else:
                strings = [value]
            for template in strings:
                if not isinstance(template, (str, int)) or isinstance(template, bool):
                    raise ValueError("SAPRouter error template must be text: %s" % key)
                try:
                    Template(str(template)).substitute(TEMPLATE_CONTEXT)
                except (KeyError, ValueError) as exc:
                    raise ValueError("Invalid SAPRouter error template for %s" %
                                     key) from exc
    count = profile["error_count"]
    if not isinstance(count["enabled"], bool):
        raise ValueError("error_profile.error_count.enabled must be boolean")
    for key in ("start", "default_error_step", "version_request_step", "route_accept_step",
                "raw_unreachable_step"):
        try:
            number = int(count[key])
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid error_profile.error_count.%s" % key) from exc
        if number < 0:
            raise ValueError("error_profile.error_count.%s must be nonnegative" %
                             key)
    if profile["partner_name_mode"] not in {"literal", "loopback"}:
        raise ValueError("Unknown error_profile.partner_name_mode")
    if not isinstance(profile["error_time_format"], str):
        raise ValueError("error_profile.error_time_format must be text")


def resolve_error_profile(release, overrides=None):
    """Resolve a service's version default and partial YAML overrides."""
    base = (DEFAULT_ERROR_PROFILE_916 if int(release) == 916
            else DEFAULT_ERROR_PROFILE_LEGACY)
    profile = deepcopy(base)
    if overrides is not None:
        _merge_profile(profile, overrides)
    _validate_profile(profile)
    return profile


def render_error_options(profile, case, context, reason=None):
    """Render one named reply without mutating the shared resolved profile."""
    options = dict(profile["errors"][case])
    lines = options.pop("line_by_reason", None)
    if lines is not None:
        if reason not in lines:
            raise ValueError("Unknown invalid-route reason: %s" % reason)
        options.setdefault("line", lines[reason])
    for key, value in options.items():
        if key in {"return_code", "count_step", "count_after"}:
            options[key] = int(value)
        else:
            options[key] = Template(str(value)).substitute(context)
    return options
