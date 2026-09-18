# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

"""Generic SAPRouter error-profile defaults, validation, and rendering."""

from copy import deepcopy
from string import Template

from pysap.SAPRouter import SAPRouterError


ERROR_TEXT_FIELDS = {field.name for field in SAPRouterError.fields_desc}
ROUTE_FAILURES = {"no_hops", "no_hops_one_entry", "missing_route_bytes",
                  "bad_length", "bad_entries", "zero_offset", "bad_offset",
                  "bad_rest"}
CASE_FIELDS = ERROR_TEXT_FIELDS | {"count_step", "count_after"}
TEMPLATE_CONTEXT = {
    "hostname": "host.example",
    "release": "0",
    "router_version": "40",
    "router_version_patch": "0",
    "peer_ip": "127.0.0.1",
    "target_host": "127.0.0.1",
    "target_port": "3200",
    "partner_host": "127.0.0.1",
    "listener_port": "3299",
    "opcode": "3",
    "timeout": "5",
    "route_ni_version": "0",
    "request_length": "10025",
    "max_request_length": "10024",
}


DEFAULT_ERROR_PROFILE = {
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
    "max_request_length": None,
    "oversized_request_error": False,
    "unknown_packet_error": False,
    "error_count": {
        "enabled": False,
        "start": 1,
        "default_error_step": 1,
        "version_request_step": 0,
        "route_accept_step": 0,
        "raw_unreachable_step": 0,
    },
    "errors": {
        "packet_too_big": {
            "return_code": -93,
            "error": "Network packet too big",
            "detail": "message length $request_length exceeds max ($max_request_length)",
            "count_step": 1,
        },
        "invalid_route": {
            "return_code": -93,
            "error": "internal error",
            "detail": "invalid route received",
            "line_by_reason": {reason: "" for reason in ROUTE_FAILURES},
            "count_step": 1,
        },
        "route_version_old": {
            "return_code": -96,
            "error": "invalid client version",
            "detail": "route version $route_ni_version too old",
            "count_step": 1,
        },
        "host_empty": {
            "return_code": -90,
            "error": "hostname '' unknown",
            "detail": "hostname empty",
            "count_step": 1,
        },
        "host_unknown": {
            "return_code": -90,
            "error": "hostname '$target_host' unknown",
            "detail": "hostname '$target_host' not found",
            "count_step": 1,
        },
        "service_invalid": {
            "return_code": -91,
            "error": "service '$target_port' unknown",
            "count_step": 1,
        },
        "route_expected": {
            "return_code": -93,
            "error": "internal error",
            "detail": "route expected",
            "count_step": 1,
        },
        "route_denied": {
            "return_code": -94,
            "error": "$hostname: route permission denied "
                     "($peer_ip to $target_host, $target_port)",
            "detail": "",
            "count_step": 1,
        },
        "partner_unreachable": {
            "return_code": -92,
            "error": "partner '$partner_host:$target_port' not reached",
            "detail": "",
            "count_step": 1,
        },
        "control_unknown": {
            "return_code": -13,
            "error": "invalid client version",
            "detail": "unknown opcode $opcode received",
            "count_step": 1,
        },
        "admin_info_denied": {
            "return_code": -94,
            "error": "Admin from remote denied",
            "count_step": 1,
        },
        "admin_denied": {
            "return_code": -94,
            "error": "Admin from remote denied",
            "count_step": 1,
        },
        "admin_password_denied": {
            "return_code": -94,
            "error": "route denied",
            "count_step": 1,
        },
        "timeout": {
            "return_code": -5,
            "error": "connection timed out",
            "detail": "no route received within ${timeout}s",
            "count_step": 1,
        },
    },
}


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
    if not isinstance(profile["oversized_request_error"], bool):
        raise ValueError("error_profile.oversized_request_error must be boolean")
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
    """Resolve and validate a service profile without version selection.

    ``release`` remains part of the public call contract and is available to
    rendered templates, but selecting build behavior is the caller's
    configuration responsibility.
    """
    profile = deepcopy(DEFAULT_ERROR_PROFILE)
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
