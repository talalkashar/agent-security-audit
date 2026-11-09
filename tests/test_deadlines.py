"""Wall-clock limits: one response may not outlast the timeout, and a scan stops at its time budget."""

import socket
import threading
import time
import unittest
from unittest import mock

from agent_security_audit import http, lab, runner
from agent_security_audit.http import TIME_BUDGET_MESSAGE, Client, TimeBudgetExceeded
from agent_security_audit.model import passed

FAST = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\nConnection: close\r\n\r\n<p>hello</p>\n"


def serve_drip(drip_headers=False, fast_root=False, root=FAST):
    """A stub on 127.0.0.1 that sends one byte every 0.2 s, so no single read ever times out."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    stop = threading.Event()

    def handle(conn):
        try:
            request = conn.recv(4096)
            if fast_root and request.startswith(b"GET / "):
                conn.sendall(root)
                return
            head = b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n"
            if not drip_headers:
                conn.sendall(head)
                head = b""
            for byte in head + b"a" * 200:
                if stop.is_set():
                    return
                conn.sendall(bytes([byte]))
                time.sleep(0.2)
        except OSError:
            pass
        finally:
            conn.close()

    def loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()

    def close():
        stop.set()
        srv.close()

    return f"http://127.0.0.1:{srv.getsockname()[1]}", close


class ResponseDeadlineTest(unittest.TestCase):
    def check_cut(self, drip_headers):
        url, close = serve_drip(drip_headers=drip_headers)
        try:
            c = Client(url, timeout=1.0, delay=0)
            start = time.monotonic()
            with self.assertRaises(http.ResponseTooSlow) as cm:
                c.get("/x")
            # A cut after bytes arrived is not a silent drop: checks that read TimeoutError as "no answer" must not
            # see it as one.
            self.assertNotIsInstance(cm.exception, TimeoutError)
            self.assertLess(time.monotonic() - start, 2.5)
            self.assertIn("no complete response within 1 s", str(cm.exception))
        finally:
            close()

    def test_slow_body_is_cut_at_the_timeout(self):
        self.check_cut(drip_headers=False)

    def test_slow_headers_are_cut_at_the_timeout(self):
        self.check_cut(drip_headers=True)

    def test_timer_firing_after_a_whole_response_keeps_it(self):
        class LateWatchdog(http._Watchdog):
            def finish(self):  # the timer fires after the read returned but before finish() stops it
                self.expired = True
                return super().finish()

        unframed = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<p>hello</p>\n"
        with mock.patch.object(http, "_Watchdog", LateWatchdog):
            url, close = serve_drip(fast_root=True)
            try:
                self.assertIn("hello", Client(url, timeout=1.0, delay=0).get("/").text)  # Content-Length met
            finally:
                close()
            url, close = serve_drip(fast_root=True, root=unframed)
            try:
                with self.assertRaises(http.ResponseTooSlow):  # read until close: a cut cannot be told from the end
                    Client(url, timeout=1.0, delay=0).get("/")
            finally:
                close()

    def test_fast_response_is_untouched(self):
        url, close = serve_drip(fast_root=True)
        try:
            resp = Client(url, timeout=1.0, delay=0).get("/")
            self.assertEqual(resp.status, 200)
            self.assertIn("hello", resp.text)
        finally:
            close()


def serve_secret_site():
    """127.0.0.1 stub: a slow home page with an inline script and /app.js holding a Stripe-format test key."""
    key = ("sk_" + "live_" + "a" * 30).encode()
    pages = {b"/": (b"text/html", b'<html><script>var a=1</script><script src="/app.js"></script></html>'),
             b"/app.js": (b"application/javascript", b'var k="' + key + b'";')}
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)

    def handle(conn):
        try:
            path = conn.recv(4096).split(b" ")[1]
            if path == b"/":
                time.sleep(0.6)
            ctype, body = pages.get(path, (b"text/plain", b"nf"))
            status = b"200 OK" if path in pages else b"404 Not Found"
            conn.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Type: " + ctype + b"\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        except (OSError, IndexError):
            pass
        finally:
            conn.close()

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return f"http://127.0.0.1:{srv.getsockname()[1]}", srv.close


class ScanTimeBudgetTest(unittest.TestCase):
    def test_cut_short_script_fetch_never_passes(self):
        url, close = serve_secret_site()
        try:
            opts = {"no_dns": True, "no_ports": True}
            _, full = runner.run(url, ids=["NEXT-01", "NEXT-02"], delay=0, options=opts)
            _, cut = runner.run(url, ids=["NEXT-01", "NEXT-02"], delay=0, max_time=0.5, options=opts)
        finally:
            close()
        self.assertEqual(full[0].status, "fail")
        for r in cut:
            self.assertNotEqual(r.status, "pass", (r.check_id, r.summary))
            if r.status == "error":
                self.assertTrue(r.summary.startswith("not run: time budget"), r.summary)

    def test_deadline_stops_new_requests(self):
        c = Client("http://127.0.0.1:9", delay=0, deadline=time.monotonic() - 1)
        with self.assertRaises(TimeBudgetExceeded):
            c.get("/")
        self.assertEqual(c.sent, 0)

    def test_scan_reports_not_run_after_the_budget(self):
        url, close = serve_drip(fast_root=True)
        try:
            start = time.monotonic()
            _, results = runner.run(url, timeout=0.5, delay=0, max_time=2, include_manual=False,
                                    options={"no_dns": True, "no_ports": True})
            elapsed = time.monotonic() - start
        finally:
            close()
        self.assertLess(elapsed, 8)
        stopped = [r for r in results if r.summary == TIME_BUDGET_MESSAGE]
        self.assertTrue(stopped, [(r.check_id, r.status, r.summary) for r in results])
        self.assertTrue(all(r.status == "error" for r in stopped))
        self.assertIn("not run: time budget", TIME_BUDGET_MESSAGE)


class CheckDeadlineTest(unittest.TestCase):
    def test_a_check_busy_past_the_deadline_is_abandoned(self):
        # A check stuck in CPU (a slow regex, a parser) never reaches the client's deadline test. The runner stops
        # waiting GRACE seconds after the deadline, reports it as an error and runs no later check, because the
        # abandoned thread may still write to the shared context.
        release = threading.Event()

        def busy(ctx):
            while not release.is_set():
                pass
            return passed("INFRA-04", "should never be reported")

        def quick(ctx):
            return passed("NEXT-03", "should not run after an abandoned check")
        registry = {"INFRA-04": busy, "NEXT-03": quick}
        server, url = lab.serve("fixed", 0)
        try:
            with mock.patch.object(runner, "load_all", return_value=registry):
                start = time.monotonic()
                _, results = runner.run(url, ids=["INFRA-04", "NEXT-03"], delay=0, max_time=0.5)
                elapsed = time.monotonic() - start
        finally:
            release.set()
            server.shutdown()
            server.server_close()
        self.assertLess(elapsed, 0.5 + runner.GRACE + 2)
        got = {r.check_id: r for r in results}
        self.assertEqual((got["INFRA-04"].status, got["INFRA-04"].summary), ("error", runner.OVERRAN_MESSAGE))
        self.assertEqual((got["NEXT-03"].status, got["NEXT-03"].summary), ("error", TIME_BUDGET_MESSAGE))

    def test_results_and_errors_cross_the_worker_thread(self):
        def boom(ctx):
            raise KeyError("x")
        with mock.patch.object(runner, "load_all", return_value={"INFRA-04": boom,
                                                                 "NEXT-03": lambda ctx: passed("NEXT-03", "ok")}):
            server, url = lab.serve("fixed", 0)
            try:
                _, results = runner.run(url, ids=["INFRA-04", "NEXT-03"], delay=0, max_time=30)
            finally:
                server.shutdown()
                server.server_close()
        got = {r.check_id: r for r in results}
        self.assertEqual(got["INFRA-04"].status, "error")
        self.assertIn("KeyError", got["INFRA-04"].summary)
        self.assertEqual(got["NEXT-03"].status, "pass")


if __name__ == "__main__":
    unittest.main()
