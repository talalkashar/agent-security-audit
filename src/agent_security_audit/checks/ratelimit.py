"""API-01: prove the login endpoint slows down repeated attempts (OSI layer 7)."""

from __future__ import annotations

from ..model import Result, failed, passed, warned
from . import auto

DEFAULT_BODY = '{"email":"asa-rate-limit-probe@example.invalid","password":"asa-not-a-real-password"}'
MAX_ATTEMPTS = 60
MIN_VERDICT = 10  # fewer attempts than this cannot show that no limit exists
SOFT_LIMIT_WORDS = ("too many", "rate limit", "try again later", "slow down")


@auto("API-01")
def login_rate_limit(ctx):
    path = ctx.opt("rate_limit_path")
    if not path:
        return Result("API-01", "manual", "Name the login endpoint to prove rate limiting: "
                      "--rate-limit-path /api/auth/login (MCP: rate_limit_path).", [])
    method = str(ctx.opt("rate_limit_method", "POST")).upper()
    body = ctx.opt("rate_limit_body", DEFAULT_BODY) if method not in ("GET", "HEAD") else None
    ctype = ctx.opt("rate_limit_content_type", "application/json")
    attempts = max(1, min(int(ctx.opt("rate_limit_attempts", 30)), MAX_ATTEMPTS))
    headers = {"Content-Type": ctype} if body is not None else {}
    statuses = []
    for i in range(1, attempts + 1):
        resp = ctx.client.request(method, path, headers=headers, body=body)
        statuses.append(resp.status)
        if i == 1 and resp.status in (404, 405):
            return Result("API-01", "error", f"{method} {path} answered {resp.status} on the first request; "
                          "check the path and method.", [f"first response: {resp.status}"])
        if resp.status == 429:
            retry = resp.get("retry-after")
            ev = [f"{method} {path}: {i - 1} attempts accepted, attempt {i} got 429",
                  f"retry-after: {retry or '(not set)'}"]
            if not retry:
                return warned("API-01", f"Rate limited after {i - 1} attempts, but no Retry-After header.", ev)
            return passed("API-01", f"Rate limited after {i - 1} attempts (429, Retry-After {retry}).", ev)
        if resp.status in (403, 423, 503) and any(w in resp.text.lower() for w in SOFT_LIMIT_WORDS):
            return warned("API-01", f"Throttled after {i - 1} attempts with {resp.status} instead of 429; clients and "
                          "monitoring expect 429 with Retry-After.", [f"attempt {i}: {resp.status}"])
    summary = ", ".join(f"{s}x{statuses.count(s)}" for s in sorted(set(statuses)))
    if attempts < MIN_VERDICT:
        return warned("API-01", f"No limit seen within {attempts} attempts, which is too few to judge; use at least "
                      f"{MIN_VERDICT} (default 30).", [f"{method} {path} x{attempts}: {summary}"])
    return failed("API-01", f"{attempts} login attempts from one client were all processed; nothing slowed them down.",
                  [f"{method} {path} x{attempts}: {summary}"])
