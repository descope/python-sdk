from __future__ import annotations

import asyncio
import logging
import os
from typing import Iterable

import httpx

from descope._client_base import DescopeClientBase
from descope.auth_async import AuthAsync
from descope.authmethod.enchantedlink_async import EnchantedLinkAsync
from descope.authmethod.magiclink_async import MagicLinkAsync
from descope.authmethod.oauth_async import OAuthAsync
from descope.authmethod.otp_async import OTPAsync
from descope.authmethod.password_async import PasswordAsync
from descope.authmethod.saml_async import SAMLAsync
from descope.authmethod.sso_async import SSOAsync
from descope.authmethod.totp_async import TOTPAsync
from descope.authmethod.webauthn_async import WebAuthnAsync
from descope.common import (
    DEFAULT_TIMEOUT_SECONDS,
    AccessKeyLoginOptions,
    EndpointsV1,
)
from descope.exceptions import (
    ERROR_TYPE_INVALID_TOKEN,
    AuthException,
)
from descope.http_client_async import HTTPClientAsync
from descope.management.common import MgmtV1
from descope.mgmt_async import MGMTAsync

logger = logging.getLogger(__name__)

LICENSE_HANDSHAKE_TIMEOUT_SECONDS = 5.0


class DescopeClientAsync(DescopeClientBase):
    """
    Async counterpart of DescopeClient.

    All network-bound operations — including ``validate_session`` — are
    ``async def`` because JWKS may need to be fetched. Pure JWT-claim helpers
    (``validate_permissions``, ``validate_roles``, etc.) are inherited sync
    from ``DescopeClientBase`` — they take a decoded JWT dict and run no I/O.

    The license handshake (rate-limit tier) is run lazily on the first
    management request and is also runnable eagerly via ``aopen`` /
    ``__aenter__``. Either way, it never blocks the event loop in
    ``__init__``.

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

        self._auth_http = HTTPClientAsync(
            project_id=self._project_id,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            secure=not skip_verify,
            management_key=auth_management_key or os.getenv("DESCOPE_AUTH_MANAGEMENT_KEY"),
            verbose=verbose,
        )
        self._mgmt_http = HTTPClientAsync(
            project_id=self._project_id,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            secure=not skip_verify,
            management_key=management_key or os.getenv("DESCOPE_MANAGEMENT_KEY"),
            verbose=verbose,
        )
        self._auth = AuthAsync(
            self._project_id,
            public_key,
            jwt_validation_leeway,
            http_client=self._auth_http,
        )
        self._fga_cache_url = fga_cache_url
        self._mgmt = MGMTAsync(
            http_client=self._mgmt_http,
            auth=self._auth,
            fga_cache_url=fga_cache_url,
        )

        self._magiclink = MagicLinkAsync(self._auth)
        self._enchantedlink = EnchantedLinkAsync(self._auth)
        self._oauth = OAuthAsync(self._auth)
        self._saml = SAMLAsync(self._auth)  # deprecated
        self._sso = SSOAsync(self._auth)
        self._otp = OTPAsync(self._auth)
        self._totp = TOTPAsync(self._auth)
        self._webauthn = WebAuthnAsync(self._auth)
        self._password = PasswordAsync(self._auth)

        # Lazy license handshake: any request through ``_mgmt_http`` triggers
        # ``_ensure_license`` once. Constructed on first use to avoid binding
        # the lock to an event loop that may not exist at __init__ time.
        self._license_lock: asyncio.Lock | None = None
        self._license_attempted = False
        self._mgmt_http._pre_request_hook = self._ensure_license

    @property
    def magiclink(self) -> MagicLinkAsync:
        return self._magiclink

    @property
    def enchantedlink(self) -> EnchantedLinkAsync:
        return self._enchantedlink

    @property
    def otp(self) -> OTPAsync:
        return self._otp

    @property
    def totp(self) -> TOTPAsync:
        return self._totp

    @property
    def oauth(self) -> OAuthAsync:
        return self._oauth

    # deprecated (use sso instead)
    @property
    def saml(self) -> SAMLAsync:
        return self._saml

    @property
    def sso(self) -> SSOAsync:
        return self._sso

    @property
    def webauthn(self) -> WebAuthnAsync:
        return self._webauthn

    @property
    def password(self) -> PasswordAsync:
        return self._password

    @property
    def mgmt(self) -> MGMTAsync:
        return self._mgmt

    async def aopen(self) -> DescopeClientAsync:
        """Pre-warm the license handshake. Optional.

        The handshake also runs lazily on the first management request, so
        callers may safely skip this. Use it when you want to pay the
        handshake latency at startup rather than on the first mgmt call.
        Idempotent — subsequent calls are no-ops.
        """
        await self._ensure_license()
        return self

    async def _ensure_license(self) -> None:
        """Idempotent license handshake, safe to call from concurrent requests.

        Wired as ``_mgmt_http._pre_request_hook`` so every management request
        awaits it; the lock+flag pair ensures the actual network call runs at
        most once per client instance.
        """
        if self._license_attempted:
            return
        if not self._mgmt_http.management_key:
            return
        if self._license_lock is None:
            self._license_lock = asyncio.Lock()
        async with self._license_lock:
            if self._license_attempted:
                return
            await self._fetch_rate_limit_tier_async(self._mgmt_http)
            self._license_attempted = True

    async def _fetch_rate_limit_tier_async(self, mgmt_http: HTTPClientAsync) -> None:
        """Async license handshake using a one-shot ``httpx.AsyncClient``."""
        try:
            async with httpx.AsyncClient(
                verify=mgmt_http.client_verify,
                timeout=LICENSE_HANDSHAKE_TIMEOUT_SECONDS,
            ) as client:
                response = await client.get(
                    f"{mgmt_http.base_url}{MgmtV1.license_get_path}",
                    headers={"Authorization": (f"Bearer {mgmt_http.project_id}:{mgmt_http.management_key}")},
                    follow_redirects=True,
                )
            if not response.is_success:
                logger.warning(
                    "License handshake returned non-success status %s",
                    response.status_code,
                )
                return
            tier = response.json().get("rateLimitTier")
            if tier:
                mgmt_http.rate_limit_tier = tier
        except Exception as e:
            logger.warning("License handshake failed: %s", e)

    async def aclose(self) -> None:
        """Close the underlying async HTTP clients and release connections."""
        await self._auth_http.aclose()
        await self._mgmt_http.aclose()
        # OutboundApplicationByTokenAsync owns a separate no-management-key client.
        await self._mgmt._outbound_application_by_token.aclose()

    async def __aenter__(self) -> DescopeClientAsync:
        await self.aopen()
        return self

    async def __aexit__(self, *args) -> None:
        await self.aclose()

    async def validate_session(self, session_token: str, audience: Iterable[str] | str | None = None) -> dict:
        """Validate a session token. Awaitable so JWKS can be fetched without blocking the loop."""
        return await self._auth.validate_session(session_token, audience)

    async def refresh_session(self, refresh_token: str, audience: Iterable[str] | str | None = None) -> dict:
        """Refresh a session using the refresh token. Makes an async network call."""
        self._ensure_present(refresh_token, "Refresh token is required to refresh a session", ERROR_TYPE_INVALID_TOKEN)
        return await self._auth.refresh_session(refresh_token, audience)

    async def validate_and_refresh_session(
        self,
        session_token: str,
        refresh_token: str,
        audience: Iterable[str] | str | None = None,
    ) -> dict:
        """Validate the session token; refresh it if expired."""
        self._ensure_present(session_token, "Session token is missing", ERROR_TYPE_INVALID_TOKEN)
        try:
            return await self._auth.validate_session(session_token, audience)
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
        return await self._auth.exchange_access_key(access_key, audience, login_options)

    async def select_tenant(self, tenant_id: str, refresh_token: str) -> dict:
        """Add a selected tenant claim to the JWT."""
        self._ensure_present(refresh_token, "Refresh token is required to refresh a session", ERROR_TYPE_INVALID_TOKEN)
        return await self._auth.select_tenant(tenant_id, refresh_token)

    def get_last_response(self):
        """Get the last HTTP response when verbose mode is enabled."""
        mgmt_resp = self._mgmt_http.get_last_response()
        auth_resp = self._auth_http.get_last_response()
        return mgmt_resp or auth_resp
