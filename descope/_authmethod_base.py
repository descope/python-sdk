# This is not part of the public API but a code helper.
#
# The sync / async classes below are structurally identical — same body,
# same derived ``_http``. They stay split so type checkers can ensure a
# sync auth-method class is never handed an ``AuthAsync`` (or vice versa);
# collapsing into one ``Generic[T]`` would work but loses concrete-type
# tooltips at the call sites.
from __future__ import annotations

from typing import TYPE_CHECKING

from descope.auth import Auth

if TYPE_CHECKING:
    from descope.auth_async import AuthAsync


class AuthMethodBase:
    def __init__(self, auth: Auth):
        self._auth = auth
        self._http = auth.http_client


class AsyncAuthMethodBase:
    def __init__(self, auth: AuthAsync):
        self._auth = auth
        self._http = auth.http_client
