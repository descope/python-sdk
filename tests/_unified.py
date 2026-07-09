"""
Shared base class for unified sync/async client wrappers.

Both the unit-test UnifiedClient (tests/conftest.py) and the e2e wrapper
(tests/e2e/conftest.py) inherit from this to share the invoke() pattern
without coupling e2e code to mock-oriented helpers.
"""

from __future__ import annotations

import asyncio


class UnifiedClientBase:
    """
    Wraps a DescopeClient or DescopeClientAsync with a uniform interface.

    - ``mode`` — "sync" or "async".
    - attribute access — delegated to the underlying raw client.
    - ``invoke(maybe_coro)`` — awaits coroutines (async mode) or passes values
      through as-is (sync mode), so test bodies are identical for both clients.
    """

    def __init__(self, mode: str, raw):
        self.mode = mode  # "sync" | "async"
        self._raw = raw

    def __getattr__(self, name):
        return getattr(self._raw, name)

    async def invoke(self, maybe_coro):
        """Uniformly run a sync return value or an async coroutine."""
        if asyncio.iscoroutine(maybe_coro):
            return await maybe_coro
        return maybe_coro
