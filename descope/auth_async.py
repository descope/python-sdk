from __future__ import annotations

import asyncio
import copy
import json
from typing import Iterable, Optional

from descope._auth_base import AuthBase
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_TOKEN_NAME,
    AccessKeyLoginOptions,
    EndpointsV1,
    EndpointsV2,
)
from descope.exceptions import (
    ERROR_TYPE_INVALID_ARGUMENT,
    ERROR_TYPE_INVALID_PUBLIC_KEY,
    ERROR_TYPE_INVALID_TOKEN,
    AuthException,
)
from descope.http_client_async import HTTPClientAsync


class AuthAsync(AuthBase):
    """Async counterpart of ``Auth``.

    All network I/O is awaitable; JWT validation stays sync and runs after
    JWKS is pre-warmed by ``ensure_keys``.
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        public_key: Optional[dict | str] = None,
        jwt_validation_leeway: int = 5,
        *,
        http_client: HTTPClientAsync,
    ):
        super().__init__(project_id, public_key, jwt_validation_leeway)
        self._http = http_client
        # Lazy-init: constructed on first ``ensure_keys`` to avoid
        # "no running event loop" if the client is built before the loop starts.
        self._lock_public_keys: asyncio.Lock | None = None

    @property
    def http_client(self) -> HTTPClientAsync:
        return self._http

    @property
    def lock_public_keys(self) -> asyncio.Lock:
        if self._lock_public_keys is None:
            self._lock_public_keys = asyncio.Lock()
        return self._lock_public_keys

    async def _fetch_public_keys(self) -> None:
        """Fetch JWKS via async HTTP. Caller must hold ``lock_public_keys``."""
        response = await self._http.get(f"{EndpointsV2.public_key_path}/{self.project_id}")
        jwks_data = response.text
        try:
            jwkeys_wrapper = json.loads(jwks_data)
            jwkeys = jwkeys_wrapper["keys"]
        except (ValueError, TypeError, KeyError) as e:
            raise AuthException(500, ERROR_TYPE_INVALID_PUBLIC_KEY, f"Unable to load jwks. Error: {e}")

        new_keys: dict = {}
        for key in jwkeys:
            try:
                loaded_kid, pub_key, alg = AuthAsync._validate_and_load_public_key(key)
                new_keys[loaded_kid] = (pub_key, alg)
            except AuthException:
                pass
        self.public_keys = new_keys

    async def ensure_keys(self, kid: str | None = None) -> None:
        """Pre-warm the JWKS cache.

        Idempotent: returns immediately when the cache already contains the
        requested kid (or any key, when kid is None). Otherwise serializes
        concurrent callers behind ``lock_public_keys`` and fetches once.
        """
        if self._cache_has_kid(kid):
            return
        async with self.lock_public_keys:
            if self._cache_has_kid(kid):
                return
            await self._fetch_public_keys()

    def _cache_has_kid(self, kid: str | None) -> bool:
        if not self.public_keys:
            return False
        if kid is None:
            return True
        return kid in self.public_keys

    def _validate_token(self, token: str, audience: str | None | Iterable[str] = None) -> dict:
        """Sync JWT validation. Caller must have awaited ``ensure_keys(kid)`` first.

        Stays sync because ``AuthBase`` passes ``self._validate_token`` as the
        ``token_validator`` callback into ``jwt_common.generate_jwt_response`` /
        ``generate_auth_info`` (see ``_auth_base.py``), which invoke it
        synchronously. The async ``prepare_jwt_response`` / ``prepare_auth_info``
        wrappers warm JWKS *before* that sync flow runs.
        """
        kid, alg_header = self._kid_alg_from_token(token)
        found_key = self.public_keys.get(kid)
        if found_key is None:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                "Unable to validate public key. Public key not found.",
            )
        return self._decode_and_verify_token(token, audience, found_key, alg_header)

    async def _validate_token_async(self, token: str, audience: str | None | Iterable[str] = None) -> dict:
        """Async direct-validation entrypoint: warms JWKS then runs sync validation."""
        kid, _ = self._kid_alg_from_token(token)
        await self.ensure_keys(kid)
        return self._validate_token(token, audience)

    async def prepare_jwt_response(
        self,
        response_body: dict,
        refresh_cookie: str | None,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        """Pre-warm JWKS then build the JWT response."""
        await self._ensure_keys_for_jwt_response(response_body, refresh_cookie)
        return self.generate_jwt_response(response_body, refresh_cookie, audience)

    async def prepare_auth_info(
        self,
        response_body: dict,
        refresh_token: str | None,
        user_jwt: bool,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        """Pre-warm JWKS then build the auth info dict."""
        await self._ensure_keys_for_jwt_response(response_body, refresh_token)
        return self._generate_auth_info(response_body, refresh_token, user_jwt, audience)

    async def _ensure_keys_for_jwt_response(self, response_body: dict, refresh_token: str | None = None) -> None:
        """Pre-warm JWKS for tokens that ``generate_jwt_response`` will validate.

        Mirrors the token-extraction logic in ``jwt_common.generate_auth_info``:
        validates ``sessionJwt`` and ``refreshJwt`` from the body, or the
        provided ``refresh_token`` when ``refreshJwt`` is absent.
        """
        kids_seen: set[str] = set()
        for body_key in ("sessionJwt", "refreshJwt"):
            tok = response_body.get(body_key, "")
            if not tok:
                continue
            try:
                kid, _ = self._kid_alg_from_token(tok)
            except AuthException:
                continue
            if kid in kids_seen:
                continue
            kids_seen.add(kid)
            await self.ensure_keys(kid)
        if not response_body.get("refreshJwt") and refresh_token:
            try:
                kid, _ = self._kid_alg_from_token(refresh_token)
            except AuthException:
                return
            if kid not in kids_seen:
                await self.ensure_keys(kid)

    async def exchange_token(self, uri: str, code: str, audience: Optional[Iterable[str] | str] = None) -> dict:
        if not code:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "exchange code is empty")

        body = AuthAsync._compose_exchange_body(code)
        response = await self._http.post(uri, body=body)
        return await self.prepare_jwt_response(
            response.json(), response.cookies.get(REFRESH_SESSION_COOKIE_NAME), audience
        )

    async def exchange_access_key(
        self,
        access_key: str,
        audience: str | Iterable[str] | None = None,
        login_options: AccessKeyLoginOptions | None = None,
    ) -> dict:
        body = {
            "loginOptions": (
                {k: v for k, v in login_options.__dict__.items() if v is not None} if login_options else {}
            ),
        }
        server_response = await self._http.post(EndpointsV1.exchange_auth_access_key_path, body=body, pswd=access_key)
        return await self.prepare_auth_info(
            response_body=server_response.json(),
            refresh_token=None,
            user_jwt=False,
            audience=audience,
        )

    async def validate_token(self, token: str, audience: str | None | Iterable[str] = None) -> dict:
        """Public token-validation entrypoint (parity with ``Auth.validate_token``)."""
        return await self._validate_token_async(token, audience)

    async def validate_session(self, session_token: str, audience: str | None | Iterable[str] = None) -> dict:
        if not session_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Session token is required for validation",
            )

        res = await self._validate_token_async(session_token, audience)
        res[SESSION_TOKEN_NAME] = copy.deepcopy(res)
        return self.adjust_properties(res, True)

    async def refresh_session(self, refresh_token: str, audience: str | None | Iterable[str] = None) -> dict:
        if not refresh_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Refresh token is required to refresh a session",
            )

        await self._validate_token_async(refresh_token, audience)

        response = await self._http.post(EndpointsV1.refresh_token_path, body={}, pswd=refresh_token)
        effective_refresh = response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None) or refresh_token
        return await self.prepare_jwt_response(response.json(), effective_refresh, audience)

    async def validate_and_refresh_session(
        self,
        session_token: str,
        refresh_token: str,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        if not session_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Session token is missing",
            )

        try:
            return await self.validate_session(session_token, audience)
        except AuthException:
            if not refresh_token:
                raise AuthException(
                    400,
                    ERROR_TYPE_INVALID_TOKEN,
                    "Refresh token is missing",
                )
            return await self.refresh_session(refresh_token, audience)

    async def select_tenant(
        self,
        tenant_id: str,
        refresh_token: str,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        if not refresh_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Refresh token is required to refresh a session",
            )

        response = await self._http.post(EndpointsV1.select_tenant_path, body={"tenant": tenant_id}, pswd=refresh_token)
        return await self.prepare_jwt_response(
            response.json(), response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience
        )
