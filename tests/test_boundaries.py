import io
import http.client
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import httpx
import jwt

from auth_lab.auth import DEMO_KEY, SERVICE_KEY, login, user_id
from auth_lab.gateway import create_app as gateway
from auth_lab.orders import create_app as orders
from auth_lab.tooling import fetch_public_text, read_workspace, summarize, update_plan


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.orders = orders()
        self.client = TestClient(gateway(httpx.ASGITransport(app=self.orders)))
        self.bob = {"Authorization": "Bearer " + login("bob", "bob-demo")}
        self.alice = {"Authorization": "Bearer " + login("alice", "alice-demo")}

    def test_login_and_docs(self):
        result = self.client.post("/auth/login", json={"username": "bob", "password": "bob-demo"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(user_id("Bearer " + result.json()["access_token"]), 2)
        self.assertEqual(self.client.get("/docs").status_code, 200)
        self.assertEqual(self.client.get("/health").json()["status"], "ok")
        self.assertEqual(self.client.get("/demo").status_code, 200)

    def test_login_invalid_and_cross_origin(self):
        self.assertEqual(self.client.post("/auth/login", json={"username": "bob", "password": "wrong"}).status_code, 401)
        self.assertEqual(self.client.post("/auth/login", headers={"Origin": "http://other.test"},
                                         json={"username": "bob", "password": "bob-demo"}).status_code, 403)

    def test_all_order_routes_require_identity(self):
        for method, path in [("GET", "/api/orders"), ("GET", "/api/orders/1"), ("POST", "/api/orders/1/reorder")]:
            with self.subTest(path=path):
                self.assertEqual(self.client.request(method, path, headers={"Content-Type": "application/json"}).status_code, 401)

    def test_own_and_other_order_missing_are_indistinguishable(self):
        self.assertEqual(self.client.get("/api/orders/3", headers=self.bob).json()["items"], ["mug"])
        other = self.client.get("/api/orders/1", headers=self.bob)
        missing = self.client.get("/api/orders/999", headers=self.bob)
        self.assertEqual((other.status_code, other.json()), (404, missing.json()))

    def test_unscoped_fixture_query_demonstrates_the_removed_guard(self):
        # A local read-only fixture query recreates the missing-predicate mistake.
        row = self.orders.state.orders.connection.execute("SELECT * FROM orders WHERE id = ?", (1,)).fetchone()
        self.assertEqual(row["user_id"], 1)
        self.assertEqual(self.client.get("/api/orders/1", headers=self.bob).status_code, 404)

    def test_inbound_user_and_service_headers_cannot_spoof_identity(self):
        headers = {**self.bob, "X-User-Id": "1", "X-Service-Token": SERVICE_KEY}
        self.assertEqual(self.client.get("/api/orders/1", headers=headers).status_code, 404)
        self.assertEqual([x["id"] for x in self.client.get("/api/orders", headers=headers).json()], [3])

    def test_reorder_has_same_ownership_guard_and_no_failed_write(self):
        before = len(self.orders.state.orders.list_for(2))
        self.assertEqual(self.client.post("/api/orders/1/reorder", headers=self.bob, json={}).status_code, 404)
        self.assertEqual(len(self.orders.state.orders.list_for(2)), before)
        result = self.client.post("/api/orders/3/reorder", headers=self.bob, json={})
        self.assertEqual((result.status_code, result.json()["user_id"], result.json()["items"]), (201, 2, ["mug"]))

    def test_direct_orders_requires_gateway_identity(self):
        direct = TestClient(self.orders)
        self.assertEqual(direct.get("/orders/1", headers={"X-User-Id": "1"}).status_code, 401)
        self.assertEqual(direct.get("/orders/1", headers={"X-User-Id": "1", "X-Service-Token": SERVICE_KEY}).status_code, 200)
        self.assertEqual(direct.get("/orders/1", headers={"X-User-Id": "2", "X-Service-Token": SERVICE_KEY}).status_code, 404)

    def test_installer_requires_auth_json_origin_and_version(self):
        self.assertEqual(self.client.post("/api/update", json={"target": "1.2.3"}).status_code, 401)
        self.assertEqual(self.client.post("/api/update", headers={**self.bob, "Content-Type": "text/plain"},
                                          content='{"target":"1.2.3"}').status_code, 415)
        self.assertEqual(self.client.post("/api/update", headers={**self.bob, "Origin": "http://other.test"},
                                          json={"target": "1.2.3"}).status_code, 403)
        for target in ["https://invalid.example/pkg", "../pkg", "--index-url", "pkg @ file:///tmp/x"]:
            self.assertEqual(self.client.post("/api/update", headers=self.bob, json={"target": target}).status_code, 400)
        result = self.client.post("/api/update", headers=self.bob, json={"target": "1.2.3"})
        self.assertFalse(result.json()["executed"])
        self.assertEqual(result.json()["command_arguments"][-1], "example-local-tool==1.2.3")

    def test_settings_auth_scope_redaction(self):
        values = {"provider": "demo", "model": "synthetic", "api_key": "synthetic-key"}
        self.assertEqual(self.client.post("/api/settings", json=values).status_code, 401)
        result = self.client.post("/api/settings", headers=self.bob, json=values)
        self.assertEqual(result.status_code, 200)
        self.assertNotIn("synthetic-key", result.text)
        self.assertEqual(set(self.client.app.state.settings), {2})

    def test_workspace_summary_and_escape_denial(self):
        self.assertEqual(self.client.post("/api/summarize", headers=self.bob,
                         json={"kind": "file", "value": "readme.txt"}).status_code, 200)
        self.assertEqual(self.client.post("/api/summarize", headers=self.bob,
                         json={"kind": "file", "value": "../../auth_lab/auth.py"}).status_code, 400)

    def test_public_url_tool_errors_are_controlled(self):
        for error in [ValueError("private host"), http.client.BadStatusLine("private host"),
                      http.client.IncompleteRead(b"private host")]:
            with self.subTest(error=type(error).__name__), patch("auth_lab.gateway.fetch_public_text", side_effect=error):
                result = self.client.post("/api/summarize", headers=self.bob, json={"kind": "url", "value": "https://example.test"})
            self.assertEqual(result.status_code, 400)
            self.assertNotIn("private host", result.text)

    def test_forwarding_preserves_only_expected_headers(self):
        seen = []
        def handler(request):
            seen.append(request)
            return httpx.Response(200, json=[])
        client = TestClient(gateway(httpx.MockTransport(handler)))
        client.get("/api/orders", headers={**self.bob, "traceparent": "test-trace", "Accept-Language": "en",
                                          "X-User-Id": "1", "X-Arbitrary": "ignore"})
        self.assertEqual(seen[0].headers["X-User-Id"], "2")
        self.assertEqual(seen[0].headers["traceparent"], "test-trace")
        self.assertEqual(seen[0].headers["accept-language"], "en")
        self.assertNotIn("x-arbitrary", seen[0].headers)

    def test_backend_unavailable(self):
        def fail(request):
            raise httpx.ConnectError("offline", request=request)
        client = TestClient(gateway(httpx.MockTransport(fail)))
        self.assertEqual(client.get("/api/orders", headers=self.bob).status_code, 502)


class ToolTests(unittest.TestCase):
    def test_version_whitelist(self):
        for target in ["1.2.3", "1.2.3-rc1"]:
            self.assertFalse(update_plan(target)["executed"])
        for target in ["", "1", "1.2.3 --upgrade", "/tmp/pkg", "file:///x", "a==1.2.3", "1.2.3\n"]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                update_plan(target)

    def test_file_budget_and_path_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "x.txt").write_text("hello", encoding="utf-8")
            self.assertEqual(read_workspace(root, "x.txt"), "hello")
            for relative in ["../other.txt", "."]:
                with self.assertRaises(ValueError):
                    read_workspace(root, relative)
            with self.assertRaises(ValueError):
                read_workspace(root, "x.txt", max_bytes=2)
        self.assertTrue(summarize("x" * 601)["truncated"])

    def test_url_syntax_rejected_before_dns(self):
        with patch("auth_lab.tooling.socket.getaddrinfo") as resolve:
            for url in ["http://example.com", "https://user:pass@example.com", "https://example.com:444/x"]:
                with self.assertRaises(ValueError):
                    fetch_public_text(url)
            resolve.assert_not_called()

    def test_any_private_dns_answer_rejected(self):
        for addresses in [["127.0.0.1"], ["93.184.216.34", "10.0.0.1"], ["::1"], ["169.254.169.254"]]:
            with self.subTest(addresses=addresses), patch("auth_lab.tooling.socket.getaddrinfo",
                    return_value=[(None, None, None, None, (address, 443)) for address in addresses]):
                with self.assertRaises(ValueError):
                    fetch_public_text("https://example.test/")

    def fetch_with(self, body=b"hello", status=200, headers=None, budget=65536):
        response = Mock()
        response.status = status
        response.getheader.side_effect = lambda name, default=None: (headers or {}).get(name, default)
        response.read1.side_effect = io.BytesIO(body).read1
        connection = Mock()
        connection.getresponse.return_value = response
        def request(*args, **kwargs):
            connection._create_connection(("example.test", 443), timeout=5)
        connection.request.side_effect = request
        addresses = [(None, None, None, None, ("93.184.216.34", 443))]
        with patch("auth_lab.tooling.socket.getaddrinfo", return_value=addresses) as resolve, \
             patch("auth_lab.tooling.http.client.HTTPSConnection", return_value=connection) as make, \
             patch("auth_lab.tooling.socket.create_connection") as connect:
            try:
                result = fetch_public_text("https://example.test/a?q=1", max_bytes=budget)
            finally:
                self.assertEqual(resolve.call_count, 1)
                self.assertEqual(make.call_args.args[:2], ("example.test", 443))
                connect.assert_called_once_with(("93.184.216.34", 443), timeout=5, source_address=None)
                connection.close.assert_called_once()
        return result

    def test_dns_is_pinned_and_original_hostname_retained(self):
        self.assertEqual(self.fetch_with(), "hello")

    def test_fetch_redirect_size_and_encoding_guards(self):
        for kwargs in [{"status": 302}, {"headers": {"Content-Length": "999999"}},
                       {"body": b"12345", "budget": 4}, {"headers": {"Content-Encoding": "gzip"}}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.fetch_with(**kwargs)

    def test_invalid_jwt_algorithm_expiry_and_identity(self):
        from fastapi import HTTPException
        for token in ["bad", jwt.encode({"sub": "2", "exp": 1}, DEMO_KEY, algorithm="HS256")]:
            with self.assertRaises(HTTPException):
                user_id("Bearer " + token)


if __name__ == "__main__":
    unittest.main()
