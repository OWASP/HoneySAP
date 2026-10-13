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

"""SAP Fiori launchpad served from a recorded bundle.

The bundle holds the responses of a real launchpad (logon page, shell, UI5
resources, OData services of the apps) with the system specific values
replaced by placeholders. Responses are filled with the system persona and
the logged on user; logons, sessions and CSRF tokens are emulated."""

# Standard imports
import gzip
import json
import os
import re
import tarfile
from base64 import b64encode, urlsafe_b64encode
from collections import OrderedDict
from datetime import datetime, timezone
from email.utils import formatdate
from os import urandom
from random import randint
from threading import Lock
from time import monotonic
from urllib.parse import parse_qsl, unquote_plus
from uuid import uuid4
# External imports
# Custom imports
from honeysap.core.logger import Loggeable
from honeysap.services.icm.odata import EntityStore, ODataError, malformed_request, \
    segment_not_found


# Request paths of the launchpad and the services it uses
FLP_PREFIXES = ("/sap/bc/ui2/", "/sap/opu/odata/", "/sap/bc/lrep/", "/sap/bc/ui5_ui5/",
                "/sap/public/bc/ui5_ui5/", "/sap/public/bc/ui2/", "/sap/public/bc/themes/",
                "/sap/public/bc/uics/", "/sap/public/bc/nwdemo_model/", "/sap/es/ina/",
                "/sap/bc/rest/themes", "/sap/bc/cts_abapvcs")
# Paths that need HTTPS on an ICM where the launchpad requires it
HTTPS_REQUIRED = ("/sap/bc/ui2/flp", "/sap/bc/ui2/start_up", "/sap/opu/odata/",
                  "/sap/bc/lrep/", "/sap/bc/ui5_ui5/")
LOGON_PATH = "/sap/bc/ui2/flp"
# Query parameters that only defeat caches
CACHE_BUSTERS = {"_", "sap-cache", "sap-context-token", "sap-cache-id", "version",
                 "sap-ui-dist-version"}
CACHE_TOKEN = re.compile(r"~[^/~]+~")
CLIENT_SEGMENT = re.compile(r"~client-[^/~]+")
# Cacheable responses UI2 serves only to requests carrying a cache id
CACHE_ID_PATHS = ("/sap/bc/ui2/start_up",)
UNCACHED_HEADERS = [("cache-control", "no-store, no-cache"), ("pragma", "no-cache"),
                    ("expires", "-1")]
STATIC_PATHS = re.compile(r"^/sap/public/bc/(ui5_ui5|themes|ui2/logon|uics|nwdemo_model)/|"
                          r"\.(js|css|properties|json|png|jpg|gif|svg|woff2?|ttf|ico)$",
                          re.IGNORECASE)
MODIFYING_METHODS = ("POST", "PUT", "PATCH", "MERGE", "DELETE")
ODATA_SERVICE = re.compile(r"^(/sap/opu/odata/[^/]+/[^/]+/)(.*)$", re.IGNORECASE)
SERVICE_NAME = re.compile(r"^/sap/opu/odata/([^/]+)/([^/;]+)(?:;v=(\d+))?", re.IGNORECASE)
ENTITY_SET = re.compile(r"^[A-Za-z_]\w*$")
# Part headers of answers computed from the entity store
ODATA_PART_HEAD = ("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
                   "cache-control: no-store, no-cache\r\ndataserviceversion: 2.0\r\n\r\n")

# Well-known default and trial credentials accepted by default
DEFAULT_CREDENTIALS = [
    {"user": "SAP*", "password": "06071992"},
    {"user": "SAP*", "password": "PASS"},
    {"user": "DDIC", "password": "19920706"},
    {"user": "EARLYWATCH", "password": "SUPPORT"},
    {"user": "TMSADM", "password": "PASSWORD"},
    {"user": "SAPCPIC", "password": "ADMIN"},
    {"user": "DEVELOPER", "password": "ABAPtr2025#SP00"},
    {"user": "DDIC", "password": "ABAPtr2025#SP00"},
    {"user": "SAP*", "password": "ABAPtr2025#SP00"},
    {"user": "SYSTEM", "password": "ABAPtr2025#SP00"},
]
AUTH_MODES = ("list", "accept_any", "reject_all")
SESSION_TTL = 3600
MAX_SESSIONS = 10000
# Host header values used in responses; others are replaced by the persona
AUTHORITY = re.compile(r"^([A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.?|\[[0-9A-Fa-f:.]+\])(:\d{1,5})?$")
# SAP component of the sample services, in their error messages
COMPONENTS = {"SEPMRA_SHOP": "BC-SRV-NWD-FRA", "SEPMRA_PROD_MAN": "BC-SRV-NWD-FRA"}
SAP_NOTE = "See SAP Note 1797736 for error analysis " \
           "(https://service.sap.com/sap/support/notes/1797736)"
BATCH_SAP_NOTE = "See SAP Note 1869434 for details about working with $batch " \
                 "(https://service.sap.com/sap/support/notes/1869434)"
SAP_TRANSACTION = "For backend administrators: use ADT feed reader \"SAP Gateway Error Log\" " \
                  "or run transaction /IWFND/ERROR_LOG on SAP Gateway hub system and search " \
                  "for entries with the timestamp above for more details"
XML_ERROR_NAMESPACE = "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"
XML_DETAIL_ORDER = ("ContentID", "code", "message", "propertyref", "severity", "target",
                    "transition")


def _random_token(length):
    return urlsafe_b64encode(urandom(length)).decode("ascii").rstrip("=")


def _perf_fesrec():
    return "%d.000000" % randint(800, 30000)


def _xml_text(value):
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def wants_json(accept, query):
    """SAP Gateway answers JSON to $format=json or an Accept header asking
    for it, Atom XML otherwise"""
    requested = dict(parse_qsl(query, keep_blank_values=True)).get("$format", "")
    if requested:
        return requested == "json"
    return "json" in (accept or "").lower()


class FioriBundle(object):
    """Index of the recorded launchpad responses."""

    _loaded = {}
    _lock = Lock()

    @classmethod
    def load(cls, path):
        """Bundle for a path, loaded once and shared by the services using it."""
        key = os.path.realpath(path)
        with cls._lock:
            if key not in cls._loaded:
                cls._loaded[key] = cls(path)
            return cls._loaded[key]

    def __init__(self, path):
        self.files = {}
        if os.path.isdir(path):
            with open(os.path.join(path, "index.json")) as f:
                index = json.load(f)
            for name in os.listdir(os.path.join(path, "files")):
                with open(os.path.join(path, "files", name), "rb") as f:
                    self.files[name] = f.read()
        else:
            with tarfile.open(path, "r:*") as tar:
                index = json.load(tar.extractfile("index.json"))
                for member in tar.getmembers():
                    if member.isfile() and member.name.startswith("files/"):
                        self.files[member.name[6:]] = tar.extractfile(member).read()
        self.routes = {}
        for route in index["routes"]:
            key = (route["method"], self.normalize_path(route["path"]))
            self.routes.setdefault(key, []).append(route)
        self.batch = {}
        for part in index["batch"]:
            self.batch.setdefault((self.normalize_path(part["service"]),
                                   self.normalize_line(part["request"])),
                                  part["file"])
        # Service roots, in lower case
        self.services = {match.group(1).lower() for match in
                         (ODATA_SERVICE.match(route["path"]) for route in index["routes"])
                         if match}
        self.services.update(part["service"].lower() for part in index["batch"])
        self.entities = self.entity_store(index)
        self.compressed = {}

    def gzipped(self, name):
        """Compressed file, compressed once"""
        if name not in self.compressed:
            self.compressed[name] = gzip.compress(self.files[name], compresslevel=6)
        return self.compressed[name]

    def entity_store(self, index):
        """Entity sets recorded in full answer the queries not recorded"""
        store = EntityStore()
        # Headers of the direct responses per entity set
        self.entity_headers = {}
        for route in index["routes"]:
            match = ODATA_SERVICE.match(route["path"])
            if route["method"] == "GET" and match and match.group(2) == "$metadata":
                for entry in route["responses"]:
                    if entry["status"] == 200 and entry["file"] in self.files:
                        store.add_metadata(match.group(1), self.files[entry["file"]])
            if route["method"] != "GET" or not match or not ENTITY_SET.match(match.group(2)):
                continue
            for entry in route["responses"]:
                if entry["status"] == 200 and entry["file"] in self.files:
                    store.add(match.group(1), match.group(2), self.files[entry["file"]],
                              route["query"].get("$expand", ""))
                    self.entity_headers.setdefault((match.group(1), match.group(2)), entry)
        for part in index["batch"]:
            method, _, target = part["request"].partition(" ")
            path, _, query = target.partition("?")
            data = self.files.get(part["file"], b"")
            head, _, body = data.partition(b"\r\n\r\n")
            if method == "GET" and ENTITY_SET.match(path) and head.startswith(b"HTTP/1.1 200"):
                store.add(part["service"], path, body,
                          dict(parse_qsl(query, keep_blank_values=True)).get("$expand", ""))
        return store

    def known_service(self, path):
        match = ODATA_SERVICE.match(path if path.endswith("/") else path + "/")
        return bool(match) and match.group(1).lower() in self.services

    def query_entities(self, service, resource, query, as_json=True):
        """Answer of the entity store as (content type, bytes), or None.
        Invalid requests raise ODataError; only JSON is answered."""
        options = dict(parse_qsl(query, keep_blank_values=True))
        if options.get("$format", "json") not in ("json", "xml", "atom"):
            raise malformed_request()
        text = self.entities.query(service, unquote_plus(resource), options)
        if text is None or not as_json:
            return None
        content_type = "text/plain; charset=utf-8" if resource.endswith("/$count") else \
            "application/json; charset=utf-8"
        return content_type, text.encode("utf-8")

    @staticmethod
    def normalize_path(path):
        return CLIENT_SEGMENT.sub("~client-{{CLIENT}}", CACHE_TOKEN.sub("~{{CACHE}}~", path))

    @staticmethod
    def normalize_query(query, client=None):
        pairs = {}
        for name, value in parse_qsl(query, keep_blank_values=True):
            if name.lower() in CACHE_BUSTERS:
                continue
            if name.lower() == "sap-client":
                value = "{{CLIENT}}"
            pairs[name] = value
        return pairs

    def normalize_line(self, line):
        """Normalize the request line of a batch part."""
        method, _, target = line.partition(" ")
        target = target.split(" HTTP/")[0]
        path, _, query = target.partition("?")
        pairs = sorted(self.normalize_query(unquote_plus(query)).items())
        return "%s %s?%s" % (method, path, "&".join("%s=%s" % pair for pair in pairs))

    def find(self, method, path, query, state=None):
        """Best recorded route for a request, or None. Routes having a
        response for the session state (auth/unauth) are preferred, then the
        closest query."""
        candidates = self.routes.get((method, self.normalize_path(path)))
        if not candidates and method == "HEAD":
            candidates = self.routes.get(("GET", self.normalize_path(path)))
        if not candidates:
            return None
        wanted = self.normalize_query(query)
        best, best_score = None, None
        for route in candidates:
            recorded = route["query"]
            score = sum(1 for name, value in wanted.items() if recorded.get(name) == value) - \
                sum(1 for name in recorded if name not in wanted)
            if recorded == wanted:
                score += 100
            if state is not None and any(entry["state"] == state for entry in route["responses"]):
                score += 1000
            if best_score is None or score > best_score:
                best, best_score = route, score
        return best


class FioriSession(object):

    def __init__(self, user, client, language):
        self.user = user
        self.client = client
        self.language = language
        self.id = _random_token(33) + "%3d"
        self.csrf = _random_token(18) + "=="
        self.sso = b64encode(urandom(438)).decode("ascii")
        self.last_seen = monotonic()


class FioriLaunchpad(Loggeable):
    """Launchpad emulation used by the ICM service."""

    def __init__(self, service, config):
        self.service = service
        self.persona = service.persona
        self.config = config
        bundle = config.get("bundle")
        if not bundle:
            raise ValueError("fiori_launchpad.bundle is required")
        self.bundle = FioriBundle.load(bundle)
        self.require_https = config.get("require_https", False)
        self.auth_mode = config.get("auth_mode", "list")
        if self.auth_mode not in AUTH_MODES:
            raise ValueError("fiori_launchpad.auth_mode must be one of %s" % ", ".join(AUTH_MODES))
        self.credentials = config.get("credentials") or DEFAULT_CREDENTIALS
        # Sessions by id, the least recently used first
        self.sessions = OrderedDict()
        self.max_sessions = config.get("max_sessions", MAX_SESSIONS)
        self.lock = Lock()

    # Request selection

    def handles(self, request):
        path = request.path.lower()
        return path == LOGON_PATH or any(path.startswith(prefix) for prefix in FLP_PREFIXES)

    def is_static(self, request):
        return bool(STATIC_PATHS.search(request.path))

    # Sessions and credentials

    def session_cookie_name(self, client):
        return "SAP_SESSIONID_%s_%s" % (self.persona.sid, client)

    def cookies(self, request):
        cookies = {}
        for header in (value for name, value in request.headers if name.lower() == "cookie"):
            for item in header.split(";"):
                name, _, value = item.strip().partition("=")
                cookies[name] = value
        return cookies

    def session(self, request):
        cookies = self.cookies(request)
        now = monotonic()
        with self.lock:
            for session_id in [key for key, session in self.sessions.items()
                               if now - session.last_seen > SESSION_TTL]:
                del self.sessions[session_id]
            for name, value in cookies.items():
                if name.startswith("SAP_SESSIONID_") and value in self.sessions:
                    session = self.sessions[value]
                    session.last_seen = now
                    self.sessions.move_to_end(value)
                    return session
        return None

    def valid_credentials(self, user, password):
        """The client is not checked: logons to any client are accepted."""
        if self.auth_mode == "accept_any":
            return bool(user and password)
        if self.auth_mode == "reject_all":
            return False
        for credential in self.credentials:
            if credential.get("user", "").upper() == user.upper() and \
               credential.get("password") == password:
                return True
        return False

    def profile(self, user):
        for credential in self.credentials:
            if credential.get("user", "").upper() == user.upper() and \
               (credential.get("first_name") or credential.get("last_name")):
                return credential.get("first_name", ""), credential.get("last_name", "")
        profile = self.config.get("default_profile") or {}
        return profile.get("first_name", user.capitalize()), profile.get("last_name", "")

    # Responses

    def placeholders(self, request, connection, session):
        client = session.client if session else self.service.client(request)
        user = session.user if session else ""
        first_name, last_name = self.profile(user) if session else ("", "")
        local_address = connection.server.server_address[0] if connection else None
        authority = self.authority(request) or self.persona.hostname
        return [(b"{{SID}}", self.persona.sid), (b"{{CLIENT}}", client),
                (b"{{IP}}", self.persona.address(local_address)),
                (b"{{HOSTNAME}}", self.persona.hostname),
                (b"{{INSTNO}}", self.persona.instance_number),
                (b"{{USER}}", user), (b"{{FIRST_NAME}}", first_name),
                (b"{{LAST_NAME}}", last_name),
                (b"{{CSRF_TOKEN}}", session.csrf if session else ""),
                (b"{{AUTHORITY}}", authority),
                (b"{{LOGIN_XSRF}}", _random_token(32) + "=")]

    @staticmethod
    def authority(request):
        """Host header of the request when it is a valid host name"""
        host = (request.header("Host") or "").strip()
        return host if AUTHORITY.match(host) else None

    @staticmethod
    def fill(data, placeholders):
        for placeholder, value in placeholders:
            if placeholder in data:
                data = data.replace(placeholder, value.encode("utf-8"))
        return data

    def build(self, request, connection, session, entry, extra_cookies=(), body=None):
        placeholders = self.placeholders(request, connection, session)
        # Recorded files without placeholders are compressed once
        static = body is None and not entry["template"]
        if body is None:
            body = self.bundle.files[entry["file"]]
        if entry["template"]:
            body = self.fill(body, placeholders)
        compress = entry["gzip"] and "gzip" in (request.header("Accept-Encoding") or "")
        if compress and static:
            body = self.bundle.gzipped(entry["file"])
        elif compress:
            body = gzip.compress(body, compresslevel=6)
        headers = [("set-cookie", value) for _, value in extra_cookies]
        for cookie in entry["cookies"]:
            if cookie["name"].startswith("sap-usercontext"):
                headers.append(self.service.usercontext_cookie(request))
        has_length = False
        for name, value in entry["headers"]:
            if value == "{{CONTENT_LENGTH}}":
                has_length = True
                value = str(len(body))
            elif value == "{{DATE}}":
                value = formatdate(usegmt=True)
            elif value == "{{CONTENT_ENCODING}}":
                if not compress:
                    continue
                value = "gzip"
            elif name.lower() == "sap-perf-fesrec":
                value = _perf_fesrec()
            elif name.lower() == "connection" and not request.keep_alive:
                value = "close"
            else:
                value = self.fill(value.encode("utf-8"), placeholders).decode("utf-8")
            headers.append((name, value))
        if not has_length:
            # Older bundles without the recorded header order
            position = next((i + 1 for i, (name, _) in enumerate(headers)
                             if name.lower() == "content-type"), len(headers))
            headers.insert(position, ("content-length", str(len(body))))
            if compress:
                headers.append(("content-encoding", "gzip"))
        if request.path in CACHE_ID_PATHS and "sap-cache-id" not in request.query:
            headers = self.uncached(headers)
        status = entry["status"]
        reason = entry.get("reason") or self.service.reason(status)
        return self.service.response(request, status, reason, headers, body)

    @staticmethod
    def uncached(headers):
        """Replace the caching headers of a cacheable response."""
        position = next((i for i, (name, _) in enumerate(headers)
                         if name.lower() in ("cache-control", "last-modified")), None)
        if position is None:
            return headers
        headers = [(name, value) for name, value in headers
                   if name.lower() not in ("cache-control", "last-modified", "pragma", "expires")]
        return headers[:position] + UNCACHED_HEADERS + headers[position:]

    def select(self, route, session):
        state = "auth" if session else "unauth"
        for entry in route["responses"]:
            if entry["state"] == state:
                return entry
        for entry in route["responses"]:
            if entry["state"] == "any":
                return entry
        return route["responses"][0]

    # Request handling

    def handle(self, request, connection):
        if self.require_https and request.scheme != "https" and \
           any(request.path.lower().startswith(p) for p in HTTPS_REQUIRED):
            return self.service.error_response(request, 403, "Forbidden - SSL required",
                                               "403 Forbidden - SSL required",
                                               sap_system=True)
        session = self.session(request)
        if request.path.lower() == LOGON_PATH and request.method == "POST":
            return self.logon(request, connection)
        if request.path.lower().endswith(";sap-fesr-only"):
            return self.service.response(request, 204, "No Content", [
                ("content-length", "0"), ("sap-server", "true"),
                ("sap-perf-fesrec", _perf_fesrec())], b"")

        if session is None:
            session = self.basic_logon(request, connection)

        if session is not None and request.path.lower().startswith("/sap/opu/odata/"):
            rejected = self.check_csrf(request, session,
                                       required=request.method in MODIFYING_METHODS)
            if rejected is not None:
                return rejected
        if request.path.endswith("/$batch") and request.method == "POST":
            if session is None:
                return self.service.icf_auth(request, connection)
            return self.batch(request, connection, session)

        response = self.respond(request, connection, session)
        if session is not None and response.status < 400:
            self.csrf_header(request, response, session)
        return response

    @staticmethod
    def csrf_header(request, response, session):
        """The token is sent right after sap-authenticated, and only to
        requests fetching it."""
        headers = [(name, value) for name, value in response.headers
                   if name.lower() != "x-csrf-token"]
        if (request.header("x-csrf-token") or "").lower() == "fetch":
            position = next((i + 1 for i, (name, _) in enumerate(headers)
                             if name.lower() == "sap-authenticated"), len(headers))
            headers.insert(position, ("x-csrf-token", session.csrf))
        response.headers = headers

    def respond(self, request, connection, session):
        route = self.bundle.find(request.method, request.path, request.query,
                                 "auth" if session else "unauth")
        if session is not None and request.method in ("GET", "HEAD") and (
                route is None or route["query"] != self.bundle.normalize_query(request.query)):
            response = self.entity_response(request, connection, session)
            if response is not None:
                return response
        if route is None:
            if session is None and not self.public(request):
                return self.unauthenticated(request, connection)
            if self.is_service_root(request) and self.bundle.known_service(request.path):
                return self.service_document(request, session)
            return self.not_found(request, connection, session)
        if route["auth_required"] and session is None:
            return self.unauthenticated(request, connection)
        if request.method in MODIFYING_METHODS:
            self.log_modification(connection, request, session)
        return self.build(request, connection, session, self.select(route, session),
                          self.logon_page_cookies(request, route, session))

    def entity_response(self, request, connection, session):
        """Query not recorded, answered from the recorded entity sets"""
        match = ODATA_SERVICE.match(request.path)
        if not match:
            return None
        as_json = wants_json(request.header("Accept"), request.query)
        try:
            answer = self.bundle.query_entities(match.group(1), match.group(2), request.query,
                                                as_json)
        except ODataError as error:
            return self.error_response(request, session, error, as_json)
        if answer is None:
            return None
        content_type, body = answer
        entity_set = re.match(r"[A-Za-z_]\w*", match.group(2))
        entry = self.bundle.entity_headers.get(
            (match.group(1), entity_set.group(0) if entity_set else ""))
        if entry is None:
            entry = {"status": 200, "reason": "OK", "gzip": True, "template": True,
                     "cookies": [], "headers": [
                         ["content-type", content_type],
                         ["content-length", "{{CONTENT_LENGTH}}"],
                         ["sap-authenticated", "true"], ["dataserviceversion", "2.0"],
                         ["cache-control", "no-store, no-cache"], ["sap-server", "true"],
                         ["sap-perf-fesrec", ""], ["content-encoding", "{{CONTENT_ENCODING}}"]]}
        entry = dict(entry, template=True, headers=[
            [name, content_type if name.lower() == "content-type" else value]
            for name, value in entry["headers"]])
        return self.build(request, connection, session, entry, body=body)

    @staticmethod
    def is_service_root(request):
        """Root of an OData service, used by clients to fetch a CSRF token"""
        match = ODATA_SERVICE.match(request.path.rstrip("/") + "/")
        return request.method in ("GET", "HEAD") and bool(match) and not match.group(2)

    def service_document(self, request, session):
        body = json.dumps({"d": {"EntitySets": []}}).encode()
        return self.service.response(request, 200, "OK", [
            ("content-type", "application/json; charset=utf-8"),
            ("content-length", str(len(body))),
            ("dataserviceversion", "2.0"),
            ("cache-control", "no-store, no-cache"),
            ("sap-authenticated", "true"),
            ("sap-server", "true"),
            ("sap-perf-fesrec", _perf_fesrec())], body)

    def public(self, request):
        return request.path.lower().startswith(("/sap/public/",))

    def unauthenticated(self, request, connection):
        """Without a session documents get the logon page, other requests the
        ICF logon challenge."""
        accept = request.header("Accept") or ""
        if request.method == "GET" and "text/html" in accept and \
           not request.path.lower().startswith("/sap/opu/"):
            route = self.bundle.find("GET", LOGON_PATH, "", "unauth")
            if route is not None:
                return self.build(request, connection, None, self.select(route, None),
                                  self.logon_page_cookies(request, route, None))
        return self.service.icf_auth(request, connection)

    def logon_page_cookies(self, request, route, session):
        if session is not None or not any(cookie["name"].startswith("sap-login-XSRF")
                                          for entry in route["responses"]
                                          for cookie in entry["cookies"]):
            return []
        token = "%s-%s" % (datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
                           b64encode(urandom(16)).decode("ascii").replace("=", "%3d"))
        return [("set-cookie", "sap-login-XSRF_%s=%s; %s" % (
            self.persona.sid, token, self.cookie_attributes(request, http_only=True)))]

    def cookie_attributes(self, request, http_only=False):
        attributes = ["path=/"]
        if http_only:
            attributes.append("HttpOnly")
        if request.scheme == "https":
            attributes += ["SameSite=None", "secure"]
        return "; ".join(attributes)

    def form(self, request):
        return {name: value for name, value in
                parse_qsl(request.body.decode("latin-1"), keep_blank_values=True)}

    def logon(self, request, connection):
        request.credentials_logged = True
        form = self.form(request)
        user = form.get("sap-user", "")[:12]
        password = form.get("sap-password", "")
        client = self.service.client(request, form.get("sap-client", ""))
        language = (form.get("sap-language") or self.persona.language).upper()
        success = self.valid_credentials(user, password)
        connection.session.add_event("FLP logon attempt", data={
            "user": user, "password": password, "client": client,
            "language": language, "success": success,
            "auth_mode": self.auth_mode})
        if not success:
            route = self.bundle.find("POST", LOGON_PATH, "", "unauth")
            return self.build(request, connection, None, route["responses"][0],
                              self.logon_page_cookies(request, route, None))
        session = FioriSession(user.upper(), client, language)
        with self.lock:
            self.sessions[session.id] = session
            while len(self.sessions) > self.max_sessions:
                self.sessions.popitem(last=False)
        attributes = self.cookie_attributes(request)
        domain = self.sso_domain(request)
        domain = "; domain=%s" % domain if domain else ""
        location = "/sap/bc/ui2/flp?sap-client=%s&sap-language=%s" % (client, language)
        headers = [
            ("set-cookie", "sap-login-XSRF_%s=0; expires=Tue, 01-Jan-1980 00:00:01 GMT; %s"
             % (self.persona.sid, attributes)),
            ("set-cookie", "MYSAPSSO2=%s; path=/%s%s" % (
                session.sso.replace("+", "%2b").replace("/", "%2f").replace("=", "%3d"),
                domain, attributes[len("path=/"):])),
            ("set-cookie", "%s=%s; %s" % (self.session_cookie_name(client), session.id,
                                          attributes)),
            ("content-type", "text/html"),
            ("content-length", "0"),
            ("sap-authenticated", "false"),
            ("location", location),
            ("sap-server", "true"),
            ("sap-perf-fesrec", _perf_fesrec())]
        return self.service.response(request, 302, "Moved temporarily", headers, b"")

    def sso_domain(self, request):
        """Domain of the logon ticket: the request host without its first
        label, as the ICM derives it (".168.88.9" for 192.168.88.9)."""
        host = self.authority(request) or ""
        if host.startswith("["):
            return None
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        if not host:
            host = "%s.%s" % (self.persona.hostname, self.persona.domain) \
                if self.persona.domain else ""
        if host.count(".") < 2:
            return None
        return "." + host.split(".", 1)[1]

    def basic_logon(self, request, connection):
        """Requests may carry Basic credentials instead of a session."""
        credentials = self.service.basic_credentials(request)
        if credentials is None:
            return None
        user, password = credentials
        client = self.service.client(request)
        success = self.valid_credentials(user, password)
        connection.session.add_event("FLP logon attempt", data={
            "user": user, "password": password, "client": client,
            "method": "basic", "success": success, "auth_mode": self.auth_mode})
        if success:
            return FioriSession(user.upper(), client, self.persona.language)
        return None

    def check_csrf(self, request, session, required=True):
        """SAP Gateway validates a CSRF token sent with any request and
        requires one for modifying requests."""
        token = request.header("x-csrf-token")
        if token is None and not required:
            return None
        if token is not None and token.lower() == "fetch" and not required:
            return None
        if token == session.csrf or request.path.lower() == LOGON_PATH:
            return None
        body = b"CSRF token validation failed"
        return self.service.response(request, 403, "Forbidden", [
            ("content-type", "text/plain; charset=utf-8"),
            ("content-length", str(len(body))),
            ("sap-authenticated", "true"),
            ("x-csrf-token", "Required"),
            ("sap-processing-info", "ODataBEP=,crp=,RAL=,st=,MedCacheHub=,codeployed=X,softstate="),
            ("sap-server", "true"),
            ("sap-perf-fesrec", _perf_fesrec())], body)

    def log_modification(self, connection, request, session, part=None):
        connection.session.add_event("FLP data modification attempt", data={
            "user": session.user if session else "",
            "method": request.method, "path": request.path,
            "part": part or ""})

    # OData errors

    @staticmethod
    def service_names(path):
        """Namespace, name and version of the OData service of a path"""
        match = SERVICE_NAME.match(path)
        if not match:
            return "/SAP/", "", "0001"
        return "/%s/" % match.group(1).upper(), match.group(2).upper(), \
            "%04d" % int(match.group(3) or 1)

    def odata_error(self, error, path, as_json=True, batch=False):
        """Content type and body of an SAP Gateway error. Errors raised by a
        service carry the service and their details."""
        namespace, name, version = self.service_names(path)
        now = datetime.now(timezone.utc)
        transaction = uuid4().hex.upper()
        timestamp = now.strftime("%Y%m%d%H%M%S.") + "%07d" % (now.microsecond * 10)
        application = OrderedDict([("component_id", COMPONENTS.get(name, "")),
                                   ("service_namespace", namespace), ("service_id", name),
                                   ("service_version", version)])
        resolution = OrderedDict([("SAP_Transaction", SAP_TRANSACTION), ("SAP_Note", SAP_NOTE)])
        if batch and error.details is not None:
            resolution["Batch_SAP_Note"] = BATCH_SAP_NOTE
        details = [OrderedDict([("ContentID", ""), ("code", code), ("message", message),
                                ("propertyref", ""), ("severity", "error"),
                                ("transition", False), ("target", "")])
                   for code, message in error.details or ()]
        charset = "" if error.details is None else ";charset=utf-8"
        if as_json:
            inner = OrderedDict()
            if error.details is not None:
                inner["application"] = application
            inner["transactionid"] = transaction
            inner["timestamp"] = timestamp
            inner["Error_Resolution"] = resolution
            if error.details is not None:
                inner["errordetails"] = details
            document = {"error": OrderedDict([
                ("code", error.code),
                ("message", OrderedDict([("lang", "en"), ("value", error.message)])),
                ("innererror", inner)])}
            return "application/json" + charset, \
                json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        def element(tag, value):
            return "<%s>%s</%s>" % (tag, _xml_text(value), tag) if value else "<%s/>" % tag
        body = '<?xml version="1.0" encoding="utf-8"?><error xmlns="%s">' % XML_ERROR_NAMESPACE
        body += element("code", error.code)
        body += '<message xml:lang="en">%s</message>' % _xml_text(error.message)
        if error.details is None:
            body += '<innererror xmlns="%s">' % XML_ERROR_NAMESPACE
        else:
            body += "<innererror><application>%s</application>" % "".join(
                element(tag, value) for tag, value in application.items())
        body += element("transactionid", transaction) + element("timestamp", timestamp)
        body += "<Error_Resolution>%s</Error_Resolution>" % "".join(
            element(tag, value) for tag, value in resolution.items())
        if error.details is not None:
            items = "".join("<errordetail>%s</errordetail>" % "".join(
                element(tag, str(detail[tag]).lower() if tag == "transition" else detail[tag])
                for tag in XML_DETAIL_ORDER) for detail in details)
            body += "<errordetails>%s</errordetails>" % items if items else "<errordetails/>"
        body += "</innererror></error>"
        return "application/xml" + charset, body.encode("utf-8")

    def error_response(self, request, session, error, as_json):
        content_type, body = self.odata_error(error, request.path, as_json)
        headers = [("content-type", content_type), ("content-length", str(len(body))),
                   ("sap-authenticated", "true" if session else "false"),
                   ("dataserviceversion", "1.0")]
        if error.status == 404:
            headers.append(("sap-cache-control", "-u"))
        headers += [("sap-server", "true"), ("sap-perf-fesrec", _perf_fesrec())]
        return self.service.response(request, error.status, self.service.reason(error.status),
                                     headers, body)

    def error_part(self, error, service, as_json=True):
        content_type, body = self.odata_error(error, service, as_json, batch=True)
        head = "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n" \
               "dataserviceversion: 1.0\r\n" % (error.status, self.service.reason(error.status),
                                                content_type, len(body))
        if error.status == 404:
            head += "sap-cache-control: -u\r\n"
        return head.encode() + b"\r\n" + body

    def not_found(self, request, connection, session):
        """Unknown resources of known OData services, and unknown services"""
        if not request.path.lower().startswith("/sap/opu/odata/"):
            return self.service.icf_not_found(request, connection)
        match = ODATA_SERVICE.match(request.path)
        if match and self.bundle.known_service(request.path):
            error = segment_not_found(re.split(r"[/(]", match.group(2))[0])
        else:
            namespace, name, version = self.service_names(request.path)
            error = ODataError(403, "/IWFND/MED/170", "No service found for namespace '%s', "
                               "name '%s', version '%s'" % (
                                   "" if namespace == "/SAP/" else namespace, name, version), [])
        return self.error_response(request, session, error,
                                   wants_json(request.header("Accept"), request.query))

    # $batch

    def batch(self, request, connection, session):
        content_type = request.header("Content-Type") or ""
        match = re.search(r"boundary=([^;\s]+)", content_type)
        if not match:
            return self.not_found(request, connection, session)
        service = self.bundle.normalize_path(request.path[:-len("$batch")])
        boundary = "%032X" % uuid4().int
        parts = []
        for part in request.body.split(b"--" + match.group(1).encode())[1:]:
            text = part.decode("utf-8", "replace")
            if text.startswith("--"):
                break
            changeset = re.search(r"boundary=([^;\s]+)", text.split("\r\n\r\n")[0])
            if changeset:
                parts.append(self.changeset(request, connection, session, service, text))
                continue
            line = re.search(r"\r?\n\r?\n([A-Z]+ [^\r\n]+) HTTP/1\.1", text)
            if not line:
                continue
            parts.append(self.batch_part(request, connection, session, service, text,
                                         line.group(1)))
        body = b"".join(b"--%s\r\nContent-Type: application/http\r\nContent-Length: %d\r\n"
                        b"content-transfer-encoding: binary\r\n\r\n%s\r\n"
                        % (boundary.encode(), len(part), part) for part in parts)
        body += b"--%s--\r\n" % boundary.encode()
        return self.service.response(request, 202, "Accepted", [
            ("content-type", "multipart/mixed; boundary=%s" % boundary),
            ("content-length", str(len(body))),
            ("dataserviceversion", "2.0"),
            ("cache-control", "no-cache, no-store, must-revalidate"),
            ("sap-authenticated", "true"),
            ("sap-server", "true"),
            ("sap-perf-fesrec", _perf_fesrec())], body)

    def batch_part(self, request, connection, session, service, text, line):
        """Answer of a batch part: the recorded one, one computed from the
        entity sets, the recorded direct response, or an error"""
        method, _, target = line.partition(" ")
        if method != "GET":
            self.log_modification(connection, request, session, line)
            return self.forbidden_part(service)
        placeholders = self.placeholders(request, connection, session)
        recorded = self.bundle.batch.get((service, self.bundle.normalize_line(line)))
        if recorded is not None:
            return self.fill(self.bundle.files[recorded], placeholders)
        path, _, query = target.split(" HTTP/")[0].partition("?")
        headers = re.split(r"\r?\n\r?\n", text.split(line, 1)[1], maxsplit=1)[0]
        accept = re.search(r"^accept:[ \t]*(.*?)\s*$", headers, re.IGNORECASE | re.MULTILINE)
        as_json = wants_json(accept.group(1) if accept else "", query)
        try:
            answer = self.bundle.query_entities(service, path, query, as_json)
        except ODataError as error:
            return self.error_part(error, service, as_json)
        if answer is not None:
            content_type, body = answer
            body = self.fill(body, placeholders)
            return (ODATA_PART_HEAD % (content_type, len(body))).encode() + body
        route = self.bundle.find("GET", service + path, query)
        if route is None:
            return self.error_part(segment_not_found(re.split(r"[/(]", path)[0]), service,
                                   as_json)
        # The same resource requested directly
        entry = self.select(route, session)
        data = self.fill(self.bundle.files[entry["file"]], placeholders)
        head = "HTTP/1.1 %d %s\r\n" % (entry["status"], self.service.reason(entry["status"]))
        head += "".join("%s: %s\r\n" % (name, value) for name, value in entry["headers"]
                        if not name.lower().startswith("sap-"))
        return head.encode() + b"Content-Length: %d\r\n\r\n" % len(data) + data

    def forbidden_part(self, service):
        return self.error_part(ODataError(403, "/IWBEP/CM_MGW_RT/004",
                                          "You are not authorized to perform this action"),
                               service)

    def changeset(self, request, connection, session, service, text):
        """Changesets hold modifying requests: logged and refused."""
        for line in re.findall(r"\r?\n\r?\n([A-Z]+ [^\r\n]+) HTTP/1\.1", text):
            self.log_modification(connection, request, session, line)
        return self.forbidden_part(service)
