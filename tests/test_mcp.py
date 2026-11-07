"""End-to-end tests for the stdio MCP server: spawn it and speak JSON-RPC over pipes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_security_audit import lab


class Server:
    def __init__(self):
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "agent_security_audit.mcp_server"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", env=env)
        self.next_id = 0

    def send_raw(self, line):
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def read(self):
        line = self.proc.stdout.readline()
        if not line:
            raise AssertionError("server closed stdout")
        return json.loads(line)

    def request(self, method, params=None):
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.send_raw(json.dumps(msg))
        reply = self.read()
        assert reply["id"] == self.next_id, reply
        return reply

    def notify(self, method):
        self.send_raw(json.dumps({"jsonrpc": "2.0", "method": method}))

    def call(self, name, arguments=None):
        reply = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        return reply["result"]

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        self.proc.stdout.close()


class McpServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = Server()
        reply = cls.srv.request("initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}})
        cls.init = reply["result"]
        cls.srv.notify("notifications/initialized")

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_initialize(self):
        self.assertEqual(self.init["protocolVersion"], "2025-03-26")
        self.assertEqual(self.init["capabilities"], {"tools": {}})
        self.assertEqual(self.init["serverInfo"]["name"], "agent-security-audit")
        self.assertIn("BUILD", self.init["instructions"])
        self.assertIn("VERIFY", self.init["instructions"])

    def test_initialize_unknown_version_gets_latest(self):
        srv = Server()
        try:
            r = srv.request("initialize", {"protocolVersion": "1999-01-01", "capabilities": {}})
            self.assertEqual(r["result"]["protocolVersion"], "2025-06-18")
        finally:
            srv.close()

    def test_ping(self):
        self.assertEqual(self.srv.request("ping")["result"], {})

    def test_tools_list(self):
        tools = {t["name"]: t for t in self.srv.request("tools/list")["result"]["tools"]}
        self.assertEqual(set(tools), {"list_checks", "get_check", "build_rules", "run_scan"})
        for t in tools.values():
            self.assertEqual(t["inputSchema"]["type"], "object")
            self.assertTrue(t["description"])
        self.assertEqual(tools["get_check"]["inputSchema"]["required"], ["id"])
        scan = tools["run_scan"]["inputSchema"]
        self.assertEqual(scan["required"], ["target"])
        for key in ("authorized", "checks", "areas", "stacks", "auto_only", "rate_limit_path", "rate_limit_method",
                    "rate_limit_body", "rate_limit_attempts", "allow_supabase", "supabase_tables", "no_dns", "no_ports",
                    "format"):
            self.assertIn(key, scan["properties"])
        self.assertEqual(scan["properties"]["format"]["enum"], ["json", "md", "html"])

    def test_list_checks(self):
        res = self.srv.call("list_checks", {"area": "browser"})
        self.assertFalse(res["isError"])
        data = json.loads(res["content"][0]["text"])
        self.assertTrue(data["count"] > 0)
        self.assertTrue(all(c["area"] == "browser" for c in data["checks"]))

    def test_get_check(self):
        res = self.srv.call("get_check", {"id": "browser-03"})
        self.assertFalse(res["isError"])
        text = res["content"][0]["text"]
        self.assertIn("BROWSER-03", text)
        self.assertIn("nosniff", text)

    def test_get_check_unknown_is_tool_error(self):
        res = self.srv.call("get_check", {"id": "NOPE-99"})
        self.assertTrue(res["isError"])

    def test_bad_arguments_are_tool_errors(self):
        self.assertTrue(self.srv.call("get_check", {})["isError"])
        self.assertTrue(self.srv.call("list_checks", {"area": "nope"})["isError"])
        self.assertTrue(self.srv.call("list_checks", {"bogus": 1})["isError"])

    def test_build_rules(self):
        res = self.srv.call("build_rules", {"stack": ["nextjs"], "area": ["browser"]})
        self.assertFalse(res["isError"])
        text = res["content"][0]["text"]
        self.assertTrue(text.startswith("# Build rules"))
        self.assertIn("BROWSER-03", text)
        self.assertNotIn("## auth", text)

    def _scan(self, mode, **extra):
        server, url = lab.serve(mode)
        try:
            res = self.srv.call("run_scan", {"target": url, "no_dns": True, **extra})
        finally:
            server.shutdown()
            server.server_close()
        self.assertFalse(res["isError"], res["content"][0]["text"])
        return res["content"][0]["text"]

    def test_scan_fixed_lab(self):
        data = json.loads(self._scan("fixed", areas=["browser", "nextjs"]))
        status = {r["check_id"]: r["status"] for r in data["results"]}
        self.assertEqual(status["BROWSER-03"], "pass")
        self.assertNotIn("manual", status.values())  # auto_only defaults to true
        self.assertEqual(data["counts"]["fail"], 0)

    def test_scan_vulnerable_lab(self):
        data = json.loads(self._scan("vulnerable", areas=["browser", "nextjs"]))
        results = {r["check_id"]: r for r in data["results"]}
        self.assertEqual(results["BROWSER-03"]["status"], "fail")
        self.assertTrue(results["BROWSER-03"]["summary"])

    def test_scan_returns_fix_first_summary(self):
        server, url = lab.serve("vulnerable")
        try:
            res = self.srv.call("run_scan", {"target": url, "no_dns": True, "checks": ["BROWSER-03"]})
        finally:
            server.shutdown()
            server.server_close()
        self.assertFalse(res["isError"])
        json.loads(res["content"][0]["text"])  # the report itself stays plain JSON
        summary = res["content"][1]["text"]
        self.assertIn("Fix these first:", summary)
        self.assertIn("BROWSER-03", summary)

    def test_scan_html(self):
        text = self._scan("vulnerable", checks=["BROWSER-03"], format="html")
        self.assertTrue(text.startswith("<!doctype html>"))
        self.assertIn("BROWSER-03", text)

    def test_scan_markdown(self):
        text = self._scan("vulnerable", checks=["BROWSER-03"], format="md")
        self.assertIn("BROWSER-03", text)

    def test_scan_schema_documents_active_probes(self):
        tools = {t["name"]: t for t in self.srv.request("tools/list")["result"]["tools"]}
        self.assertIn("Active", tools["run_scan"]["description"])

    def test_unknown_method(self):
        r = self.srv.request("does/not/exist")
        self.assertEqual(r["error"]["code"], -32601)

    def test_unknown_tool(self):
        r = self.srv.request("tools/call", {"name": "nope", "arguments": {}})
        self.assertEqual(r["error"]["code"], -32602)

    def test_malformed_json(self):
        self.srv.send_raw("{not json")
        r = self.srv.read()
        self.assertEqual(r["error"]["code"], -32700)
        self.assertIsNone(r["id"])
        # The server is still alive afterwards.
        self.assertEqual(self.srv.request("ping")["result"], {})

    def test_notifications_get_no_reply(self):
        self.srv.notify("notifications/initialized")
        self.srv.notify("some/unknown/notification")
        # The next reply must belong to this ping, not to the notifications.
        self.assertEqual(self.srv.request("ping")["result"], {})


if __name__ == "__main__":
    unittest.main()
