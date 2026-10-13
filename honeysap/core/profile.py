# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2.

"""Small, service-neutral helpers for resolving profile data."""

from copy import deepcopy


def merge_profile(base, overlay, list_mergers=None):
    """Return a deep merge of two mappings without mutating either input.

    ``list_mergers`` optionally maps a key to a function receiving
    ``(base_value, overlay_value)`` and returning the merged list.
    Unregistered lists use replacement semantics.
    """
    if not isinstance(base, dict) or not isinstance(overlay, dict):
        raise ValueError("profile values must be mappings")
    list_mergers = list_mergers or {}
    result = deepcopy(base)
    for key, value in overlay.items():
        if (key in list_mergers and isinstance(value, list) and
                isinstance(result.get(key), list)):
            result[key] = list_mergers[key](deepcopy(result[key]),
                                            deepcopy(value))
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_profile(result[key], value, list_mergers)
        else:
            result[key] = deepcopy(value)
    return result


def resolve_named_profiles(definitions, defaults=None, label="profile"):
    """Resolve named mappings with optional ``extends`` inheritance."""
    if not isinstance(definitions, dict):
        raise ValueError("%s definitions must be a mapping" % label)
    defaults = defaults or {}
    if not isinstance(defaults, dict):
        raise ValueError("%s defaults must be a mapping" % label)
    resolving = []
    resolved = {}

    def resolve(name):
        if name in resolved:
            return deepcopy(resolved[name])
        if name in resolving:
            cycle = " -> ".join(resolving + [name])
            raise ValueError("Cyclic %s inheritance: %s" % (label, cycle))
        if name in definitions:
            value = definitions[name]
        elif name in defaults:
            return deepcopy(defaults[name])
        else:
            raise ValueError("Unknown %s parent: %s" % (label, name))
        if not isinstance(value, dict):
            raise ValueError("%s %s must be a mapping" % (label, name))
        resolving.append(name)
        parent = value.get("extends")
        if parent is None:
            result = {}
        else:
            if not isinstance(parent, str):
                raise ValueError("%s %s.extends must be a string" %
                                 (label, name))
            result = resolve(parent)
        overlay = {key: item for key, item in value.items()
                   if key != "extends"}
        result = merge_profile(result, overlay)
        resolving.pop()
        resolved[name] = result
        return deepcopy(result)

    return {name: resolve(name) for name in definitions}


def resolve_profile(default, overlay=None, label="profile"):
    """Merge one profile overlay, supporting ``extends`` when requested."""
    if overlay is None:
        overlay = {}
    if not isinstance(overlay, dict):
        raise ValueError("%s overlay must be a mapping" % label)
    if "extends" not in overlay:
        return merge_profile(default, overlay)
    resolved = resolve_named_profiles(
        {"default": default, "overlay": overlay}, label=label)
    return resolved["overlay"]


def render_profile_values(values, context, numeric_fields=()):
    """Render scalar profile values without mutating the source mapping."""
    from string import Template

    numeric_fields = set(numeric_fields)
    rendered = {}
    for key, value in values.items():
        if key in numeric_fields:
            rendered[key] = int(value)
        else:
            rendered[key] = Template(str(value)).substitute(context)
    return rendered
