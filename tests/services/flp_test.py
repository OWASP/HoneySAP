# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

# Standard imports
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import Mock
# Custom imports
from honeysap.core.config import Configuration
from honeysap.core.http import HTTPRequest
from honeysap.services.icm.icm import SAPICMService


LOGON_PAGE = (b'<html><body><form><input type="hidden" name="sap-client" value="{{CLIENT}}">'
              b'<input name="sap-login-XSRF" value="{{LOGIN_XSRF}}"></form></body></html>')
FAILED_PAGE = b"<html><body>Client, name, or password is not correct; log on again</body></html>"
SHELL = b"<html><body>Launchpad of {{SID}} for {{USER}}</body></html>"
START_UP = b'{"client":"{{CLIENT}}","id":"{{USER}}","fullName":"{{FIRST_NAME}} {{LAST_NAME}}","system":"{{SID}}"}'
RESOURCE = b"sap.ui.define([],function(){});"
ENTITIES = b'{"d":{"results":[{"__metadata":{"uri":"https://{{AUTHORITY}}/sap/opu/odata/sap/SRV/Items(1)"}}]}}'
THINGS = json.dumps({"d": {"__count": "3", "results": [
    {"__metadata": {"uri": "https://{{AUTHORITY}}/sap/opu/odata/sap/SRV/Things(%d)" % n,
                    "type": "SRV.Thing"}, "Id": n, "Name": name}
    for n, name in ((1, "one"), (2, "two"), (3, "three"))]}}).encode()
PART = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n"
        b'{"d":"one"}')


def response(file_id, state="auth", status=200, headers=None, cookies=(), template=True,
             gzip=False):
    return {"status": status, "reason": "", "file": file_id, "state": state,
            "template": template, "gzip": gzip, "text": True,
            "cookies": [{"name": name, "attributes": []} for name in cookies],
            "headers": headers or [["content-type", "text/html; charset=utf-8"],
                                   ["content-length", "{{CONTENT_LENGTH}}"],
                                   ["sap-authenticated", "true"],
                                   ["sap-server", "true"],
                                   ["sap-perf-fesrec", "1.000000"],
                                   ["content-encoding", "{{CONTENT_ENCODING}}"]]}


def route(method, path, responses, query=None, auth_required=True):
    return {"method": method, "path": path, "query": query or {}, "auth_required": auth_required,
            "csrf_fetch": False, "label": "", "responses": responses}


class FioriLaunchpadTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.bundle = tempfile.mkdtemp()
        files = {"logon": LOGON_PAGE, "failed": FAILED_PAGE, "shell": SHELL,
                 "startup": START_UP, "resource": RESOURCE, "entities": ENTITIES,
                 "part": PART, "things": THINGS}
        os.mkdir(os.path.join(cls.bundle, "files"))
        for name, data in files.items():
            with open(os.path.join(cls.bundle, "files", name), "wb") as f:
                f.write(data)
        index = {"routes": [
            route("GET", "/sap/bc/ui2/flp",
                  [response("logon", "unauth", cookies=["sap-login-XSRF_{{SID}}", "sap-usercontext"]),
                   response("shell")], auth_required=False),
            route("POST", "/sap/bc/ui2/flp", [response("failed", "unauth")], auth_required=False),
            route("GET", "/sap/bc/ui2/start_up", [response("startup")],
                  query={"sap-client": "{{CLIENT}}"}),
            route("GET", "/sap/public/bc/ui5_ui5/1/resources/~{{CACHE}}~/sap/m/library.js",
                  [response("resource", gzip=True, template=False)], auth_required=False),
            route("GET", "/sap/bc/ui2/start_up", [response("startup", headers=[
                ["content-type", "application/json; charset=utf-8"],
                ["content-length", "{{CONTENT_LENGTH}}"], ["sap-authenticated", "true"],
                ["cache-control", "private, max-age=29030400"],
                ["last-modified", "Mon, 12 Oct 2026 14:35:27 GMT"],
                ["x-content-type-options", "nosniff"], ["sap-server", "true"]])],
                  query={"sap-client": "{{CLIENT}}", "so": "*", "action": "*"}),
            route("GET", "/sap/opu/odata/sap/SRV/Items", [response("entities", headers=[
                ["content-type", "application/json"], ["content-length", "{{CONTENT_LENGTH}}"],
                ["sap-authenticated", "true"], ["x-csrf-token", "{{CSRF_TOKEN}}"],
                ["dataserviceversion", "2.0"], ["sap-server", "true"]])]),
            route("GET", "/sap/opu/odata/sap/SRV/Things", [response("things", headers=[
                ["content-type", "application/json; charset=utf-8"],
                ["content-length", "{{CONTENT_LENGTH}}"], ["sap-authenticated", "true"],
                ["dataserviceversion", "2.0"], ["sap-server", "true"]])],
                  query={"$inlinecount": "allpages"}),
            route("GET", "/sap/bc/rest/themes/~client-{{CLIENT}}/themelist/v1/~v=UI5:1.136.10",
                  [response("resource", status=403)]),
        ], "batch": [{"service": "/sap/opu/odata/sap/SRV/", "request": "GET One?$top=1",
                      "file": "part"}]}
        with open(os.path.join(cls.bundle, "index.json"), "w") as f:
            json.dump(index, f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.bundle)

    def setUp(self):
        self.service = SAPICMService(Configuration({
            "virtual": True,
            "system": {"sid": "PRD", "hostname": "sapprd01", "client": "100"},
            "fiori_launchpad": {"enabled": True, "bundle": self.bundle,
                                "credentials": [{"user": "DEVELOPER", "password": "secret",
                                                 "first_name": "Ada", "last_name": "Lovelace"}]}}),
            Mock(), Mock(), Mock())
        self.connection = Mock()
        self.connection.server.server_address = ("192.0.2.1", 44300)

    def request(self, method, target, headers=None, body=b"", scheme="https"):
        request = HTTPRequest(method, target, "HTTP/1.1", [("Host", "sap.example:44300")] +
                              list(headers or []), body, b"", scheme=scheme)
        return self.service.handle_request(request, self.connection)

    def logon(self, user="DEVELOPER", password="secret"):
        body = ("sap-user=%s&sap-password=%s&sap-client=100" % (user, password)).encode()
        return self.request("POST", "/sap/bc/ui2/flp", [
            ("Content-Type", "application/x-www-form-urlencoded")], body)

    def session_cookie(self, response):
        for name, value in response.headers:
            if name == "set-cookie" and value.startswith("SAP_SESSIONID_PRD_100="):
                return value.split(";")[0]
        return None

    def test_logon_page_is_filled(self):
        response = self.request("GET", "/sap/bc/ui2/flp?sap-client=100")
        self.assertEqual(response.status, 200)
        self.assertIn(b'name="sap-client" value="100"', response.body)
        self.assertNotIn(b"{{LOGIN_XSRF}}", response.body)
        cookies = [value for name, value in response.headers if name == "set-cookie"]
        self.assertTrue(cookies[0].startswith("sap-login-XSRF_PRD="))
        self.assertTrue(cookies[1].startswith("sap-usercontext=sap-client=100"))

    def test_https_is_optional(self):
        response = self.request("GET", "/sap/bc/ui2/flp?sap-client=100", scheme="http")
        self.assertEqual(response.status, 200)
        self.assertIn(b'name="sap-client" value="100"', response.body)
        self.service.flp.require_https = True
        response = self.request("GET", "/sap/bc/ui2/flp", scheme="http")
        self.assertEqual((response.status, response.reason), (403, "Forbidden - SSL required"))

    def test_failed_logon_is_logged(self):
        response = self.logon(password="wrong")
        self.assertIn(b"password is not correct", response.body)
        event = self.connection.session.add_event.call_args
        self.assertEqual(event.args[0], "FLP logon attempt")
        self.assertEqual(event.kwargs["data"]["password"], "wrong")
        self.assertFalse(event.kwargs["data"]["success"])

    def test_logon_session_and_persona_values(self):
        response = self.logon()
        self.assertEqual(response.status, 302)
        self.assertIn(("location", "/sap/bc/ui2/flp?sap-client=100&sap-language=EN"),
                      response.headers)
        cookie = self.session_cookie(response)
        self.assertIsNotNone(cookie)
        shell = self.request("GET", "/sap/bc/ui2/flp?sap-client=100", [("Cookie", cookie)])
        self.assertEqual(shell.body, b"<html><body>Launchpad of PRD for DEVELOPER</body></html>")
        start_up = self.request("GET", "/sap/bc/ui2/start_up?sap-client=100", [("Cookie", cookie)])
        self.assertEqual(json.loads(start_up.body),
                         {"client": "100", "id": "DEVELOPER", "fullName": "Ada Lovelace",
                          "system": "PRD"})

    def test_protected_resource_without_session(self):
        response = self.request("GET", "/sap/bc/ui2/start_up?sap-client=100")
        self.assertEqual(response.status, 401)

    def test_cache_tokens_and_gzip(self):
        response = self.request("GET", "/sap/public/bc/ui5_ui5/1/resources/~20251029090600~/"
                                       "sap/m/library.js", [("Accept-Encoding", "gzip, deflate")])
        self.assertEqual(response.status, 200)
        self.assertIn(("content-encoding", "gzip"), response.headers)
        plain = self.request("GET", "/sap/public/bc/ui5_ui5/1/resources/~X~/sap/m/library.js")
        self.assertEqual(plain.body, RESOURCE)
        self.assertNotIn("content-encoding", [name for name, _ in plain.headers])
        self.assertIn(("content-length", str(len(RESOURCE))), plain.headers)

    def test_authority_follows_the_request(self):
        cookie = self.session_cookie(self.logon())
        response = self.request("GET", "/sap/opu/odata/sap/SRV/Items", [("Cookie", cookie)])
        self.assertIn(b"https://sap.example:44300/sap/opu/odata/sap/SRV/Items(1)", response.body)

    def test_csrf_fetch_and_batch(self):
        cookie = self.session_cookie(self.logon())
        fetch = self.request("HEAD", "/sap/opu/odata/sap/SRV/",
                             [("Cookie", cookie), ("x-csrf-token", "Fetch")])
        token = dict(fetch.headers)["x-csrf-token"]
        batch = (b"--b1\r\nContent-Type: application/http\r\n\r\nGET One?$top=1 HTTP/1.1\r\n\r\n\r\n"
                 b"--b1\r\nContent-Type: application/http\r\n\r\nGET Missing HTTP/1.1\r\n\r\n\r\n"
                 b"--b1\r\nContent-Type: multipart/mixed; boundary=c1\r\n\r\n--c1\r\n"
                 b"Content-Type: application/http\r\n\r\nPOST Items HTTP/1.1\r\n\r\n{}\r\n--c1--\r\n"
                 b"--b1--\r\n")
        headers = [("Cookie", cookie), ("Content-Type", "multipart/mixed; boundary=b1")]
        rejected = self.request("POST", "/sap/opu/odata/sap/SRV/$batch", headers, batch)
        self.assertEqual(rejected.status, 403)
        self.assertIn(("x-csrf-token", "Required"), rejected.headers)
        response = self.request("POST", "/sap/opu/odata/sap/SRV/$batch",
                                headers + [("x-csrf-token", token)], batch)
        self.assertEqual(response.status, 202)
        self.assertIn(b'{"d":"one"}', response.body)
        self.assertIn(b"HTTP/1.1 404 Not Found\r\nContent-Type: application/xml\r\n", response.body)
        self.assertIn(b"Resource not found for the segment 'Missing'.", response.body)
        self.assertIn(b"HTTP/1.1 403 Forbidden", response.body)
        events = [call.args[0] for call in self.connection.session.add_event.call_args_list]
        self.assertIn("FLP data modification attempt", events)

    def test_auth_modes(self):
        launchpad = self.service.flp
        launchpad.auth_mode = "accept_any"
        self.assertTrue(launchpad.valid_credentials("ANYONE", "x"))
        launchpad.auth_mode = "reject_all"
        self.assertFalse(launchpad.valid_credentials("DEVELOPER", "secret"))

    def test_static_assets_are_not_logged_by_default(self):
        request = HTTPRequest("GET", "/sap/public/bc/ui5_ui5/1/resources/~X~/sap/m/library.js",
                              "HTTP/1.1", [], b"", b"")
        self.assertFalse(self.service.should_log(request))
        self.assertTrue(self.service.should_log(HTTPRequest("GET", "/sap/bc/ui2/start_up",
                                                            "HTTP/1.1", [], b"", b"")))

    def test_client_path_segment(self):
        cookie = self.session_cookie(self.logon())
        response = self.request("GET", "/sap/bc/rest/themes/~client-100/themelist/v1/"
                                       "~v=UI5:1.136.10", [("Cookie", cookie)])
        self.assertEqual(response.status, 403)

    def test_sso_domain_follows_the_host(self):
        def domain(host):
            request = HTTPRequest("POST", "/sap/bc/ui2/flp", "HTTP/1.1", [("Host", host)],
                                  b"", b"", scheme="https")
            return self.service.flp.sso_domain(request)
        self.assertEqual(domain("192.168.88.9:44300"), ".168.88.9")
        self.assertEqual(domain("sapprd01.corp.example"), ".corp.example")
        self.assertIsNone(domain("sapprd01:44300"))
        self.assertIsNone(domain("[2001:db8::1]:44300"))
        sso = [value for name, value in self.logon().headers
               if name == "set-cookie" and value.startswith("MYSAPSSO2=")][0]
        self.assertNotIn("domain=", sso)

    def test_csrf_token_only_on_fetch(self):
        cookie = self.session_cookie(self.logon())
        fetch = self.request("GET", "/sap/opu/odata/sap/SRV/Items",
                             [("Cookie", cookie), ("x-csrf-token", "Fetch")])
        names = [name for name, _ in fetch.headers]
        self.assertEqual(names.count("x-csrf-token"), 1)
        self.assertEqual(names.index("x-csrf-token"), names.index("sap-authenticated") + 1)
        token = dict(fetch.headers)["x-csrf-token"]
        plain = self.request("GET", "/sap/opu/odata/sap/SRV/Items",
                             [("Cookie", cookie), ("x-csrf-token", token)])
        self.assertEqual(plain.status, 200)
        self.assertNotIn("x-csrf-token", [name for name, _ in plain.headers])

    def test_start_up_is_cacheable_only_with_cache_id(self):
        cookie = self.session_cookie(self.logon())
        target = "/sap/bc/ui2/start_up?so=*&action=*&sap-client=100"
        cached = self.request("GET", target + "&sap-cache-id=ABC", [("Cookie", cookie)])
        self.assertIn(("cache-control", "private, max-age=29030400"), cached.headers)
        uncached = self.request("GET", target, [("Cookie", cookie)])
        names = [name for name, _ in uncached.headers]
        self.assertEqual(names[:6], ["content-type", "content-length", "sap-authenticated",
                                     "cache-control", "pragma", "expires"])
        self.assertIn(("cache-control", "no-store, no-cache"), uncached.headers)
        self.assertNotIn("last-modified", names)

    def test_client_is_ignored(self):
        for client in ("200", "", "x\r\nset-cookie: a=b"):
            body = ("sap-user=DEVELOPER&sap-password=secret&sap-client=%s" % client).encode()
            response = self.request("POST", "/sap/bc/ui2/flp", [
                ("Content-Type", "application/x-www-form-urlencoded")], body)
            self.assertEqual(response.status, 302)
            location = dict(response.headers)["location"]
            self.assertEqual(location, "/sap/bc/ui2/flp?sap-client=%s&sap-language=EN" %
                             (client if client == "200" else "100"))
        response = self.request("POST", "/sap/bc/ui2/flp", [
            ("Content-Type", "application/x-www-form-urlencoded")],
            b"sap-user=DEVELOPER&sap-password=secret")
        self.assertEqual(response.status, 302)

    def test_bundle_is_shared(self):
        other = SAPICMService(Configuration({
            "virtual": True,
            "fiori_launchpad": {"enabled": True, "bundle": self.bundle}}), Mock(), Mock(), Mock())
        self.assertIs(other.flp.bundle, self.service.flp.bundle)

    def test_unrecorded_queries_use_the_entity_sets(self):
        cookie = self.session_cookie(self.logon())
        json_request = [("Cookie", cookie), ("Accept", "application/json")]
        response = self.request("GET", "/sap/opu/odata/sap/SRV/Things?$skip=1&$top=1&"
                                       "$orderby=Name%20desc&$inlinecount=allpages", json_request)
        self.assertEqual(response.status, 200)
        result = json.loads(response.body)["d"]
        self.assertEqual((result["__count"], result["results"][0]["Name"]), ("3", "three"))
        self.assertIn("https://sap.example:44300/sap/opu/odata/sap/SRV/Things(3)",
                      result["results"][0]["__metadata"]["uri"])
        self.assertEqual(dict(response.headers)["dataserviceversion"], "2.0")
        count = self.request("GET", "/sap/opu/odata/sap/SRV/Things/$count", json_request)
        self.assertEqual((count.body, dict(count.headers)["content-type"]),
                         (b"3", "text/plain; charset=utf-8"))
        self.assertEqual(json.loads(self.request("GET", "/sap/opu/odata/sap/SRV/Things(2)",
                                                 json_request).body)["d"]["Name"], "two")
        fetch = self.request("HEAD", "/sap/opu/odata/sap/SRV/",
                             [("Cookie", cookie), ("x-csrf-token", "Fetch")])
        batch = (b"--b1\r\nContent-Type: application/http\r\n\r\n"
                 b"GET Things?$skip=2&$top=5&$select=Name HTTP/1.1\r\nAccept: application/json\r\n"
                 b"\r\n\r\n--b1--\r\n")
        response = self.request("POST", "/sap/opu/odata/sap/SRV/$batch", [
            ("Cookie", cookie), ("Content-Type", "multipart/mixed; boundary=b1"),
            ("x-csrf-token", dict(fetch.headers)["x-csrf-token"])], batch)
        self.assertIn(b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8", response.body)
        self.assertIn(b'"Name":"three"}]}}', response.body)
        # Without a session the logon is required
        self.assertEqual(self.request("GET", "/sap/opu/odata/sap/SRV/Things?$top=1").status, 401)

    def test_odata_errors(self):
        cookie = self.session_cookie(self.logon())
        json_request = [("Cookie", cookie), ("Accept", "application/json")]
        response = self.request("GET", "/sap/opu/odata/sap/SRV/Things?$top=x", json_request)
        self.assertEqual((response.status, dict(response.headers)["content-type"]),
                         (400, "application/json"))
        error = json.loads(response.body)["error"]
        self.assertEqual(error["message"]["value"], "Invalid system query options value")
        self.assertEqual(list(error["innererror"]), ["transactionid", "timestamp",
                                                     "Error_Resolution"])
        self.assertRegex(error["innererror"]["timestamp"], r"^\d{14}\.\d{7}$")
        # Without JSON in the Accept header errors are XML
        response = self.request("GET", "/sap/opu/odata/sap/SRV/Things?$filter=Name%20eq",
                                [("Cookie", cookie)])
        self.assertEqual((response.status, dict(response.headers)["content-type"]),
                         (400, "application/xml"))
        self.assertIn(b"<message xml:lang=\"en\">Expression expected after position 7</message>",
                      response.body)
        response = self.request("GET", "/sap/opu/odata/sap/SRV/Things(9)", json_request)
        self.assertEqual((response.status, dict(response.headers)["sap-cache-control"]), (404, "-u"))
        error = json.loads(response.body)["error"]
        self.assertEqual(error["innererror"]["application"]["service_id"], "SRV")
        self.assertEqual(error["innererror"]["errordetails"][0]["code"],
                         "/IWBEP/CX_MGW_BUSI_EXCEPTION")
        # Unknown services
        response = self.request("GET", "/sap/opu/odata/AIF/NOPE_SRV;v=2/Things", json_request)
        self.assertEqual(response.status, 403)
        error = json.loads(response.body)["error"]
        self.assertEqual(error["message"]["value"], "No service found for namespace '/AIF/', "
                                                    "name 'NOPE_SRV', version '0002'")
        self.assertEqual(error["innererror"]["errordetails"], [])
        response = self.request("GET", "/sap/opu/odata/sap/NOPE_SRV/", [("Cookie", cookie)])
        self.assertEqual(response.status, 403)
        self.assertIn(b"<component_id/><service_namespace>/SAP/</service_namespace>", response.body)
        self.assertIn(b"<errordetails/></innererror></error>", response.body)
        # Unknown entity sets of known services
        response = self.request("GET", "/sap/opu/odata/sap/SRV/Nope", json_request)
        self.assertEqual(json.loads(response.body)["error"]["message"]["value"],
                         "Resource not found for the segment 'Nope'.")

    def test_session_store_is_bounded(self):
        self.service.flp.max_sessions = 3
        cookies = [self.session_cookie(self.logon()) for _ in range(5)]
        self.assertEqual(len(self.service.flp.sessions), 3)
        self.assertEqual(self.request("GET", "/sap/bc/ui2/start_up?sap-client=100",
                                      [("Cookie", cookies[0])]).status, 401)
        self.assertEqual(self.request("GET", "/sap/bc/ui2/start_up?sap-client=100",
                                      [("Cookie", cookies[-1])]).status, 200)

    def test_invalid_host_is_not_reflected(self):
        cookie = self.session_cookie(self.logon())
        for host in ("evil.example<script>", "a.b.c; secure", "x\" onload=\"y"):
            request = HTTPRequest("GET", "/sap/opu/odata/sap/SRV/Things(1)", "HTTP/1.1", [
                ("Host", host), ("Cookie", cookie), ("Accept", "application/json")], b"", b"",
                scheme="https")
            response = self.service.handle_request(request, self.connection)
            self.assertNotIn(host.encode(), response.body)
            self.assertIn(b"https://sapprd01/", response.body)
        response = self.request("POST", "/sap/bc/ui2/flp", [
            ("Host", "a.b.c; secure"), ("Content-Type", "application/x-www-form-urlencoded")],
            b"sap-user=DEVELOPER&sap-password=secret")
        self.assertFalse(any("a.b.c" in value for name, value in response.headers))

    def test_static_files_are_compressed_once(self):
        path = "/sap/public/bc/ui5_ui5/1/resources/~1234~/sap/m/library.js"
        first = self.request("GET", path, [("Accept-Encoding", "gzip")])
        second = self.request("GET", path, [("Accept-Encoding", "gzip")])
        self.assertIs(first.body, second.body)
