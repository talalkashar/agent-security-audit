"""Wall-clock limits: one response may not outlast the timeout, and a scan stops at its time budget."""

import socket
import threading
import time
import unittest

from agent_security_audit import runner
from agent_security_audit.http import TIME_BUDGET_MESSAGE, Client, TimeBudgetExceeded

FAST = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\nConnection: close\r\n\r\n<p>hello</p>\n"


def serve_drip(drip_headers=False, fast_root=False):
    """A stub on 127.0.0.1 that sends one byte every 0.2 s, so no single read ever times out."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    stop = threading.Event()

    def handle(conn):
        try:
            request = conn.recv(4096)
            if fast_root and request.startswith(b"GET / "):
                conn.sendall(FAST)
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
            with self.assertRaises(TimeoutError) as cm:
                c.get("/x")
            self.assertLess(time.monotonic() - start, 2.5)
            self.assertIn("no complete response within 1 s", str(cm.exception))
        finally:
            close()

    def test_slow_body_is_cut_at_the_timeout(self):
        self.check_cut(drip_headers=False)

    def test_slow_headers_are_cut_at_the_timeout(self):
        self.check_cut(drip_headers=True)

    def test_fast_response_is_untouched(self):
        url, close = serve_drip(fast_root=True)
        try:
            resp = Client(url, timeout=1.0, delay=0).get("/")
            self.assertEqual(resp.status, 200)
            self.assertIn("hello", resp.text)
        finally:
            close()


class ScanTimeBudgetTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
