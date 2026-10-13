# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2.

"""SAPRouter error-profile loading, validation, and rendering."""

from pathlib import Path
from string import Template

from yaml import safe_load
from pysap.SAPRouter import SAPRouterError

from honeysap.core.profile import (render_profile_values, resolve_named_profiles,
                                   resolve_profile)


ERROR_TEXT_FIELDS = {field.name for field in SAPRouterError.fields_desc}
ROUTE_FAILURES = {"no_hops", "no_hops_one_entry", "missing_route_bytes",
                  "bad_length", "bad_entries", "zero_offset", "bad_offset",
                  "bad_rest"}
CASE_FIELDS = ERROR_TEXT_FIELDS | {"count_step", "count_after"}
TEMPLATE_CONTEXT = {
    "hostname": "host.example", "release": "0", "router_version": "40",
    "router_version_patch": "0", "peer_ip": "127.0.0.1",
    "target_host": "127.0.0.1", "target_port": "3200",
    "partner_host": "127.0.0.1", "listener_port": "3299", "opcode": "3",
    "timeout": "5", "route_ni_version": "0", "request_length": "10025",
    "max_request_length": "10024",
}


def _load_default_profile():
    path = Path(__file__).with_name("default_error_profile.yml")
    profile = safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise ValueError("SAPRouter default error profile must be a mapping")
    errors = profile.get("errors")
    if not isinstance(errors, dict):
        raise ValueError("SAPRouter default error profile errors must be a mapping")
    resolved_errors = resolve_named_profiles(errors, label="SAPRouter error")
    resolved_errors.pop("admin_denied_base", None)
    return {key: value for key, value in profile.items() if key != "errors"} | {
        "errors": resolved_errors}


DEFAULT_ERROR_PROFILE = _load_default_profile()


def _merge_profile(base, overrides):
    """Resolve an override against the built-in profile."""
    if not isinstance(overrides, dict):
        raise ValueError("error_profile must be a mapping")
    return resolve_profile(base, overrides, label="SAPRouter profile")


def _validate_profile(profile):
    allowed = {"fields", "error_time_format", "partner_name_mode",
               "max_request_length", "oversized_request_error",
               "unknown_packet_error", "error_count", "errors"}
    unknown = set(profile) - allowed
    if unknown:
        raise ValueError("Unknown error_profile key: %s" % sorted(unknown)[0])
    limit = profile["max_request_length"]
    if limit is not None:
        if isinstance(limit, bool) or not (
                isinstance(limit, int) or
                isinstance(limit, str) and limit.isdecimal()):
            raise ValueError("error_profile.max_request_length must be a positive integer or null")
        profile["max_request_length"] = int(limit)
        if profile["max_request_length"] <= 0:
            raise ValueError("error_profile.max_request_length must be a positive integer or null")
    for key in ("unknown_packet_error", "oversized_request_error"):
        if not isinstance(profile[key], bool):
            raise ValueError("error_profile.%s must be boolean" % key)

    fields = profile["fields"]
    unknown_fields = set(fields) - ERROR_TEXT_FIELDS
    if unknown_fields:
        raise ValueError("Unknown error_profile.fields key: %s" %
                         sorted(unknown_fields)[0])
    for case, options in profile["errors"].items():
        if case not in DEFAULT_ERROR_PROFILE["errors"]:
            raise ValueError("Unknown error_profile.errors key: %s" % case)
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
                    raise ValueError("Invalid SAPRouter numeric profile value: %s" % key) from exc
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
                    raise ValueError("Invalid SAPRouter error template for %s" % key) from exc

    count = profile["error_count"]
    if not isinstance(count["enabled"], bool):
        raise ValueError("error_profile.error_count.enabled must be boolean")
    for key in ("start", "default_error_step", "version_request_step",
                "route_accept_step", "raw_unreachable_step"):
        try:
            number = int(count[key])
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid error_profile.error_count.%s" % key) from exc
        if number < 0:
            raise ValueError("error_profile.error_count.%s must be nonnegative" % key)
    if profile["partner_name_mode"] not in {"literal", "loopback"}:
        raise ValueError("Unknown error_profile.partner_name_mode")
    if not isinstance(profile["error_time_format"], str):
        raise ValueError("error_profile.error_time_format must be text")


def resolve_error_profile(overrides=None):
    """Resolve and validate the built-in profile plus an optional overlay."""
    profile = _merge_profile(DEFAULT_ERROR_PROFILE, overrides or {})
    _validate_profile(profile)
    return profile


def render_error_options(profile, case, context, reason=None):
    """Render one named reply without mutating the resolved profile."""
    options = dict(profile["errors"][case])
    lines = options.pop("line_by_reason", None)
    if lines is not None:
        if reason not in lines:
            raise ValueError("Unknown invalid-route reason: %s" % reason)
        options.setdefault("line", lines[reason])
    return render_profile_values(
        options, context, {"return_code", "count_step", "count_after"})


def render_error_fields(profile, context):
    """Render the SAPRouter error-text fields without mutating the profile."""
    return render_profile_values(profile["fields"], context)
