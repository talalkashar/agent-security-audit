"""API-01: prove the login endpoint slows down repeated attempts (OSI layer 7)."""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlsplit

from ..crawl import crawl
from ..model import Result, passed, warned
from ..scope import same_origin
from . import auto, count

FAKE_EMAIL = "asa-rate-limit-probe@example.invalid"
FAKE_PASSWORD = "asa-not-a-real-password"
DEFAULT_BODY = f'{{"email":"{FAKE_EMAIL}","password":"{FAKE_PASSWORD}"}}'
MAX_ATTEMPTS = 60
MIN_VERDICT = 10  # fewer attempts than this cannot show that no limit exists
# Words that mean the server started refusing attempts. Underscores and hyphens count as spaces, so Firebase's
# TOO_MANY_ATTEMPTS_TRY_LATER matches "too many".
LIMIT_WORDS = ("too many", "rate limit", "try again later", "slow down", "locked", "lockout", "captcha",
               "temporarily blocked", "temporarily disabled")
# A crawled password form is used only when its page or action looks like a login, and never when it looks like
# sign-up or password reset, so repeated attempts cannot create accounts or send mail.
LOGIN_PATH = re.compile(r"(?i)log[-_]?in|sign[-_]?in|session|auth")
NOT_LOGIN_PATH = re.compile(r"(?i)sign[-_]?up|register|join|create|invite|reset|forgot|recover")
USER_FIELD = re.compile(r"(?i)e-?mail|user|login|account|identifier")
# 429 (handled on its own) and 423 Locked mean throttling; any other changed status (a 403, a 400, a 500 or 502) proves
# nothing without limit or lockout wording. A 403 can be a WAF or CSRF refusal, and a 5xx is the server failing.
THROTTLE_STATUSES = (423,)


def _path(url):
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def login_endpoint(ctx):
    """{path, method, body, ctype, source} for the login endpoint: --rate-limit-path, else a same-origin POST login
    form found by the crawl. None when there is neither."""
    path = ctx.opt("rate_limit_path")
    if path:
        method = str(ctx.opt("rate_limit_method", "POST")).upper()
        return {"path": path, "method": method,
                "body": ctx.opt("rate_limit_body", DEFAULT_BODY) if method not in ("GET", "HEAD") else None,
                "ctype": ctx.opt("rate_limit_content_type", "application/json"), "source": "--rate-limit-path",
                "detected": False}
    for form in crawl(ctx).forms:
        where = _path(form.page) + " " + _path(form.action)
        if (form.method != "post" or sum(t == "password" for _, t in form.inputs) != 1
                or not same_origin(ctx.target, form.action) or not LOGIN_PATH.search(where)
                or NOT_LOGIN_PATH.search(where)):
            continue
        fields = [(name, FAKE_PASSWORD if kind == "password" else FAKE_EMAIL) for name, kind in form.inputs
                  if name and (kind in ("password", "email") or (kind == "text" and USER_FIELD.search(name)))]
        return {"path": _path(form.action), "method": "POST", "body": urlencode(fields),
                "ctype": "application/x-www-form-urlencoded", "source": f"password form on {_path(form.page)}",
                "detected": True}
    return None


def _limit_words(resp):
    text = re.sub(r"[_-]+", " ", resp.text[:20000].lower())
    return {w for w in LIMIT_WORDS if w in text}


@auto("API-01")
def login_rate_limit(ctx):
    target = login_endpoint(ctx)
    if not target:
        return Result("API-01", "manual", "No login form found on the crawled pages. Name the login endpoint to prove "
                      "rate limiting: --rate-limit-path /api/auth/login (MCP: rate_limit_path).", [])
    method, path, body = target["method"], target["path"], target["body"]
    attempts = max(1, min(int(ctx.opt("rate_limit_attempts", 30)), MAX_ATTEMPTS))
    headers = {"Content-Type": target["ctype"]} if body is not None else {}
    source = f"endpoint from {target['source']}"
    statuses, base_status, base_words = [], None, set()
    for i in range(1, attempts + 1):
        resp = ctx.client.request(method, path, headers=headers, body=body)
        statuses.append(resp.status)
        if i == 1:
            if resp.status in (404, 405):
                return Result("API-01", "error", f"{method} {path} answered {resp.status} on the first request; "
                              "check the path and method.", [f"first response: {resp.status}", source])
            if target["detected"] and resp.status in (400, 403) and not _limit_words(resp):
                return Result("API-01", "manual", f"The login form at {path} refused the first attempt with "
                              f"{resp.status} (probably a CSRF token or a field the scanner did not fill). Name the "
                              "endpoint with --rate-limit-path and --rate-limit-body.", [f"first response: {resp.status}",
                                                                                         source])
            base_status, base_words = resp.status, _limit_words(resp)
        if resp.status == 429:
            retry = resp.get("retry-after")
            ev = [f"{method} {path}: {count(i - 1, 'attempt')} accepted, attempt {i} got 429",
                  f"retry-after: {retry or '(not set)'}", source]
            if not retry:
                return warned("API-01", f"Rate limited after {count(i - 1, 'attempt')}, but no Retry-After header.", ev)
            return passed("API-01", f"Rate limited after {count(i - 1, 'attempt')} (429, Retry-After {retry}).", ev)
        # Limit or lockout words the first answer did not have, or a change to 423 Locked, is throttling.
        words = sorted(_limit_words(resp) - base_words)
        changed = i > 1 and resp.status != base_status
        if words or (changed and resp.status in THROTTLE_STATUSES):
            start = i - 1
            why = f"{resp.status}" + (f" saying \"{words[0]}\"" if words else "")
            return warned("API-01", f"Throttled after {count(start, 'attempt')}: attempt {i} got {why} instead of "
                          f"{base_status}. Clients and monitoring expect 429 with Retry-After.",
                          [f"{method} {path}: " + ("attempt 1" if start == 1 else f"attempts 1-{start}")
                           + f" -> {base_status}, attempt {i} -> {resp.status}", source])
    summary = ", ".join(f"{s}x{statuses.count(s)}" for s in sorted(set(statuses)))
    ev = [f"{method} {path} x{attempts}: {summary}", source]
    errors = sum(s >= 500 for s in statuses)
    if errors and len(set(statuses)) > 1:
        return warned("API-01", f"Inconsistent responses, no limit proven: {count(errors, 'server error')} "
                      f"({', '.join(str(s) for s in sorted({s for s in statuses if s >= 500}))}) among {attempts} login "
                      "attempts, with no 429, 423 or limit wording. Check the server logs and confirm the limit in "
                      "code.", ev)
    if attempts < MIN_VERDICT:
        return warned("API-01", f"No limit seen within {count(attempts, 'attempt')}, which is too few to judge; use at least "
                      f"{MIN_VERDICT} (default 30).", ev)
    same = "every answer was the same" if len(set(statuses)) == 1 else "no answer changed in a way that shows a limit"
    return warned("API-01", f"No limit observed up to {attempts} login attempts from one client: {same}. A limit may "
                  f"sit higher; confirm it in code, or raise --rate-limit-attempts (max "
                  f"{MAX_ATTEMPTS}).", ev)
