from __future__ import annotations

import os
from typing import Iterable

from descope._client_base import DescopeClientBase
from descope.authmethod.totp_async import TOTPAsync
from descope.common import (
    DEFAULT_TIMEOUT_SECONDS,
    REFRESH_SESSION_COOKIE_NAME,
    AccessKeyLoginOptions,
    EndpointsV1,
)
from descope.exceptions import (
    ERROR_TYPE_INVALID_TOKEN,
    AuthException,
)
from descope.http_client_async import HTTPClientAsync


class DescopeClientAsync(DescopeClientBase):
    """
    Async counterpart of DescopeClient.

    All network-bound operations are ``async def`` and must be awaited.
    Pure JWT/session-validation operations (validate_session,
    validate_permissions, etc.) are inherited sync from DescopeClientBase —
    they perform no I/O.

    Usage (recommended — context manager):
        async with DescopeClientAsync(project_id="P...") as client:
            jwt = await client.refresh_session(refresh_token)

    Usage (explicit close):
        client = DescopeClientAsync(project_id="P...")
        try:
            jwt = await client.refresh_session(refresh_token)
        finally:
            await client.aclose()
    """

    def __init__(
        self,
        project_id: str,
        public_key: dict | None = None,
        skip_verify: bool = False,
        management_key: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        jwt_validation_leeway: int = 5,
        auth_management_key: str | None = None,
        fga_cache_url: str | None = None,
        *,
        base_url: str | None = None,
        verbose: bool = False,
    ):
        super().__init__(
            project_id,
            public_key,
            skip_verify,
            timeout_seconds,
            jwt_validation_leeway,
            auth_management_key,
            base_url=base_url,
            verbose=verbose,
        )

        resolved_base_url = self._auth.http_client.base_url
        self._auth_http = HTTPClientAsync(
            project_id=self._auth.project_id,
            base_url=resolved_base_url,
            timeout_seconds=timeout_seconds,
            secure=not skip_verify,
            management_key=auth_management_key or os.getenv("DESCOPE_AUTH_MANAGEMENT_KEY"),
            verbose=verbose,
        )
        self._mgmt_http = HTTPClientAsync(
            project_id=self._auth.project_id,
            base_url=resolved_base_url,
            timeout_seconds=timeout_seconds,
            secure=not skip_verify,
            management_key=management_key or os.getenv("DESCOPE_MANAGEMENT_KEY"),
            verbose=verbose,
        )
        self._fga_cache_url = fga_cache_url

        self._totp = TOTPAsync(self._auth, self._auth_http)

        if self._mgmt_http.management_key:
            self._fetch_rate_limit_tier(self._mgmt_http)

    @property
    def totp(self) -> TOTPAsync:
        return self._totp

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def aclose(self) -> None:
        """Close the underlying async HTTP clients and release connections."""
        await self._auth_http.aclose()
        await self._mgmt_http.aclose()

    async def __aenter__(self) -> DescopeClientAsync:
        return self

    async def __aexit__(self, *args) -> None:
        await self.aclose()

    # -------------------------------------------------------------------------
    # Async session methods — network I/O
    # -------------------------------------------------------------------------

    async def refresh_session(self, refresh_token: str, audience: Iterable[str] | str | None = None) -> dict:
        """Refresh a session using the refresh token. Makes an async network call."""
        self._ensure_present(refresh_token, "Refresh token is required to refresh a session", ERROR_TYPE_INVALID_TOKEN)
        # Validate token locally (pure CPU — may trigger a one-time sync key fetch on Auth)
        self._auth._validate_token(refresh_token, audience)
        response = await self._auth_http.post(EndpointsV1.refresh_token_path, body={}, pswd=refresh_token)
        resp = response.json()
        effective_refresh = response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None) or refresh_token
        return self._auth.generate_jwt_response(resp, effective_refresh, audience)

    async def validate_and_refresh_session(
        self,
        session_token: str,
        refresh_token: str,
        audience: Iterable[str] | str | None = None,
    ) -> dict:
        """
        Validate the session token; refresh it if expired.
        validate_session is sync (no I/O); refresh_session is async.
        """
        self._ensure_present(session_token, "Session token is missing", ERROR_TYPE_INVALID_TOKEN)
        try:
            return self._auth.validate_session(session_token, audience)
        except AuthException:
            self._ensure_present(refresh_token, "Refresh token is missing", ERROR_TYPE_INVALID_TOKEN)
            return await self.refresh_session(refresh_token, audience)

    async def logout(self, refresh_token: str):
        """Logout the user from the current session and revoke the refresh token."""
        self._require_refresh_token(refresh_token)
        return await self._auth_http.post(EndpointsV1.logout_path, body={}, pswd=refresh_token)

    async def logout_all(self, refresh_token: str):
        """Logout the user from all active sessions and revoke the refresh token."""
        self._require_refresh_token(refresh_token)
        return await self._auth_http.post(EndpointsV1.logout_all_path, body={}, pswd=refresh_token)

    async def me(self, refresh_token: str) -> dict:
        """Retrieve user details for the refresh token."""
        self._require_refresh_token(refresh_token)
        response = await self._auth_http.get(EndpointsV1.me_path, allow_redirects=None, pswd=refresh_token)
        return response.json()

    async def my_tenants(
        self,
        refresh_token: str,
        dct: bool = False,
        ids: list[str] | None = None,
    ) -> dict:
        """Retrieve tenant attributes that the user belongs to."""
        self._require_refresh_token(refresh_token)
        self._validate_tenant_selector(dct, ids)

        body: dict[str, bool | list[str]] = {"dct": dct}
        if ids is not None:
            body["ids"] = ids
        response = await self._auth_http.post(EndpointsV1.my_tenants_path, body=body, pswd=refresh_token)
        return response.json()

    async def history(self, refresh_token: str) -> list[dict]:
        """Retrieve user authentication history for the refresh token."""
        self._require_refresh_token(refresh_token)
        response = await self._auth_http.get(EndpointsV1.history_path, allow_redirects=None, pswd=refresh_token)
        return response.json()

    async def exchange_access_key(
        self,
        access_key: str,
        audience: Iterable[str] | str | None = None,
        login_options: AccessKeyLoginOptions | None = None,
    ) -> dict:
        """Return a new session token for the given access key."""
        self._require_access_key(access_key)
        body = {
            "loginOptions": (
                {k: v for k, v in login_options.__dict__.items() if v is not None} if login_options else {}
            ),
        }
        server_response = await self._auth_http.post(
            EndpointsV1.exchange_auth_access_key_path, body=body, pswd=access_key
        )
        return self._auth._generate_auth_info(
            response_body=server_response.json(),
            refresh_token=None,
            user_jwt=False,
            audience=audience,
        )

    async def select_tenant(self, tenant_id: str, refresh_token: str) -> dict:
        """Add a selected tenant claim to the JWT."""
        self._ensure_present(refresh_token, "Refresh token is required to refresh a session", ERROR_TYPE_INVALID_TOKEN)
        response = await self._auth_http.post(
            EndpointsV1.select_tenant_path, body={"tenant": tenant_id}, pswd=refresh_token
        )
        return self._auth.generate_jwt_response(
            response.json(), response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), None
        )

    # -------------------------------------------------------------------------
    # Debugging
    # -------------------------------------------------------------------------

    def get_last_response(self):
        """Get the last HTTP response when verbose mode is enabled."""
        mgmt_resp = self._mgmt_http.get_last_response()
        auth_resp = self._auth_http.get_last_response()
        return mgmt_resp or auth_resp
