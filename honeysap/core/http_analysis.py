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

"""Decoding and tagging of HTTP requests for the request events.

The raw request is always kept; the fields built here make events easy to
search and alert on: decoded parameters, uploaded file hashes, submitted
credentials, forwarding headers and tags for known SAP attack patterns."""

# Standard imports
import json
import re
from hashlib import sha256
from urllib.parse import parse_qsl, unquote
# External imports
# Custom imports


MAX_VALUE = 4096

# Parameter names carrying user names and passwords in SAP and common web
# logon forms
USER_FIELDS = {"sap-user", "sap-alias", "j_username", "j_user", "username", "user",
               "userid", "user_id", "uid", "login", "logonuser", "email"}
PASSWORD_FIELDS = {"sap-password", "j_password", "password", "passwd", "pass", "pwd",
                   "logonpassword", "sap-password-new", "sap-system-login-password"}

FORWARDING_HEADERS = ("x-forwarded-for", "x-real-ip", "forwarded", "true-client-ip",
                      "x-client-ip", "x-originating-ip", "client-ip", "x-forwarded-host",
                      "via")

# (tag, path pattern) for paths of known SAP attack surfaces
PATH_TAGS = [
    ("cve-2025-31324-visual-composer", r"/developmentserver/metadatauploader"),
    ("cve-2020-6287-recon", r"/ctcwebservice"),
    ("sap-java-admin", r"^/(nwa|irj/portal|webdynpro/dispatcher|sap/monitoring|"
                       r"servlet/com\.sap|ctc/|tc~)"),
    ("soap-rfc", r"^/sap/bc/soap/(rfc|wsdl)"),
    ("webgui", r"^/sap/bc/gui/sap/its/webgui"),
    ("icm-admin", r"^/sap/(admin|wdisp/admin)"),
    ("adt", r"^/sap/bc/adt"),
    ("odata", r"^/sap/opu/odata"),
    ("bsp", r"^/sap/bc/bsp"),
    ("message-server", r"^/msgserver"),
    ("ms-parameter-enum", r"^/msgserver/(text|html|xml)/parameter"),
    ("system-info", r"^/sap/public/(info|ping|icman/ping)"),
]
PATH_PATTERNS = [(tag, re.compile(pattern, re.IGNORECASE)) for tag, pattern in PATH_TAGS]
TRAVERSAL = re.compile(r"(\.\.[/\\]|%2e%2e|%252e|\.\.%2f|%c0%ae)", re.IGNORECASE)
SCANNERS = re.compile(r"(nuclei|nmap|masscan|zgrab|sqlmap|nikto|gobuster|ffuf|dirbuster|"
                      r"wfuzz|nessus|qualys|openvas|acunetix|burp|python-requests|go-http-client|"
                      r"curl/|wget/|censys|shodan|expanse|internet-measurement|httpx)",
                      re.IGNORECASE)
INJECTION = re.compile(r"(<script|javascript:|union\s+select|'\s*or\s*'1'\s*=\s*'1|"
                       r"\$\{jndi:|;\s*(cat|id|wget|curl)\s|\|\s*(id|whoami)\b|"
                       r"/etc/passwd|\bcmd\.exe\b|<%|<\?php)", re.IGNORECASE)


def _decode(data):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _pairs(text):
    return [[name, value[:MAX_VALUE]] for name, value in
            parse_qsl(text, keep_blank_values=True)]


def query_params(request):
    return _pairs(request.query) if request.query else []


def _content_type(request):
    return (request.header("Content-Type") or "").lower()


def form_params(request, parts=None):
    """Form fields of URL-encoded and multipart bodies (files excluded)."""
    content_type = _content_type(request)
    if content_type.startswith("application/x-www-form-urlencoded") and request.body:
        return _pairs(_decode(request.body))
    if parts:
        return [[part["name"], part["value"]] for part in parts if "value" in part]
    return []


def json_body(request, limit):
    content_type = _content_type(request)
    if "json" not in content_type or not request.body or len(request.body) > limit:
        return None
    try:
        return json.loads(_decode(request.body))
    except ValueError:
        return None


def multipart_parts(request):
    """Describe the parts of a multipart body: name, filename, content type,
    size, and the value of form fields or the SHA-256 of files."""
    content_type = request.header("Content-Type") or ""
    match = re.search(r'boundary="?([^";]+)"?', content_type, re.IGNORECASE)
    if not content_type.lower().startswith("multipart/") or not match:
        return None
    boundary = b"--" + match.group(1).encode("latin-1")
    parts = []
    for chunk in request.body.split(boundary)[1:]:
        if chunk.startswith(b"--"):
            break
        head, separator, payload = chunk.lstrip(b"\r\n").partition(b"\r\n\r\n")
        if not separator:
            continue
        if payload.endswith(b"\r\n"):
            payload = payload[:-2]
        headers = {}
        for line in _decode(head).split("\r\n"):
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        disposition = headers.get("content-disposition", "")
        name = re.search(r'\bname="([^"]*)"', disposition)
        filename = re.search(r'filename\*?="?([^";]*)"?', disposition)
        part = {"name": name.group(1) if name else "",
                "filename": unquote(filename.group(1)) if filename else "",
                "content_type": headers.get("content-type", ""),
                "size": len(payload)}
        if filename:
            part["sha256"] = sha256(payload).hexdigest()
        else:
            part["value"] = _decode(payload)[:MAX_VALUE]
        parts.append(part)
    return parts


def credentials(pairs):
    """User name and password submitted as parameters, or None."""
    user = password = None
    fields = []
    for name, value in pairs:
        lower = name.lower()
        if lower in PASSWORD_FIELDS and password is None:
            password = value
            fields.append(name)
        elif lower in USER_FIELDS and user is None:
            user = value
            fields.append(name)
    if password is None:
        return None
    return {"user": user or "", "password": password, "fields": fields}


def forwarded_for(request):
    values = {}
    for name, value in request.headers:
        if name.lower() in FORWARDING_HEADERS:
            values.setdefault(name.lower(), []).append(value)
    return {name: ", ".join(value) for name, value in values.items()}


def tags(request, parts=None):
    """Tags for known SAP attack surfaces and attack patterns."""
    found = [tag for tag, pattern in PATH_PATTERNS if pattern.search(request.path)]
    target = unquote(request.target)
    if TRAVERSAL.search(request.target) or TRAVERSAL.search(target):
        found.append("path-traversal")
    if INJECTION.search(target) or INJECTION.search(_decode(request.body[:MAX_VALUE * 4])):
        found.append("injection-pattern")
    names = [name.lower() for name, _ in request.headers]
    if "transfer-encoding" in names and "content-length" in names:
        found.append("request-smuggling-te-cl")
    if names.count("content-length") > 1 or names.count("transfer-encoding") > 1:
        found.append("request-smuggling-duplicate-length")
    if SCANNERS.search(request.header("User-Agent") or ""):
        found.append("scanner-user-agent")
    if not request.header("User-Agent"):
        found.append("no-user-agent")
    if parts and any(part.get("filename") for part in parts):
        found.append("file-upload")
    if request.path.endswith(("/$batch", "$batch")):
        found.append("odata-batch")
    if request.method not in ("GET", "HEAD", "POST", "OPTIONS"):
        found.append("method-%s" % request.method.lower())
    return found
