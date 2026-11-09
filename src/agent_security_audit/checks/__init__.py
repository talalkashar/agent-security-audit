"""Automated proof tests.

Each automated check is a function `fn(ctx) -> Result` registered with @auto("ID"). Checks in the
catalog with mode "auto" must have exactly one registered function; tests enforce that.
"""

from __future__ import annotations

from dataclasses import dataclass, field

REGISTRY = {}


def auto(check_id):
    def wrap(fn):
        if check_id in REGISTRY:
            raise ValueError(f"{check_id} registered twice")
        REGISTRY[check_id] = fn
        fn.check_id = check_id
        return fn
    return wrap


@dataclass
class Context:
    target: str
    client: object
    options: dict = field(default_factory=dict)
    cache: dict = field(default_factory=dict)
    authorized: bool = False
    owned: bool = False  # authorized, or a local dev host: active probes may run

    @property
    def https(self):
        return self.target.startswith("https://")

    def opt(self, name, default=None):
        value = self.options.get(name)
        return default if value in (None, "") else value


def count(n, one, many=None):
    """'1 file' / '2 files'. Pass `many` for irregular plurals ('1 library' / '2 libraries')."""
    return f"{n} {one if n == 1 else (many or one + 's')}"


def are(n):
    """The verb that agrees with a count: 'is' for 1, 'are' otherwise."""
    return "is" if n == 1 else "are"


def load_all():
    """Import every check module so its @auto functions register."""
    from . import browser, cms, dns_email, exposure, network, nextjs_version, ratelimit, supabase, transport, webapp  # noqa: F401
    return REGISTRY
