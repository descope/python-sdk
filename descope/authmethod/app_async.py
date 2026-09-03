from __future__ import annotations

from typing import Optional

from descope._authmethod_base import AsyncAuthMethodBase
from descope.authmethod._app_base import AppBase
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class AppAsync(AppBase, AsyncAuthMethodBase):
    """Async Federated App (OIDC only - see AppBase) auth-method. ``start`` is I/O-free but
    stays ``async def`` for a consistent call shape; ``exchange_token`` does a real
    coroutine-based network call."""

    async def start(
        self,
        app_id: str,
        return_url: str,
        tenant: Optional[str] = None,
        login_hint: Optional[str] = None,
        scope: Optional[str] = None,
        state: Optional[str] = None,
        flow: Optional[str] = None,
    ) -> dict:
        """Build the sign-in redirect URL for an OIDC Federated App; see ``App.start`` (the
        sync equivalent) for the full explanation."""
        self._validate_app_id(app_id)
        self._validate_return_url(return_url)

        code_verifier, code_challenge = self._generate_pkce_pair()
        resolved_state = state if state else self._generate_random_token()
        url = self._compose_oidc_authorize_url(
            self._http.base_url,
            self._auth.project_id,
            app_id,
            return_url,
            tenant if tenant else "",
            login_hint if login_hint else "",
            scope if scope else "openid",
            resolved_state,
            code_challenge,
            flow if flow else "",
        )
        return {"url": url, "state": resolved_state, "code_verifier": code_verifier}

    async def exchange_token(
        self,
        app_id: str,
        code: str,
        code_verifier: Optional[str] = None,
        client_secret: Optional[str] = None,
        redirect_uri: Optional[str] = None,
    ) -> dict:
        """Exchange a Federated App authorization code for tokens; see
        ``App.exchange_token`` (the sync equivalent) for the full explanation - confirmed
        with a live end-to-end test."""
        self._validate_app_id(app_id)
        if not code:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "code cannot be empty")

        body = self._compose_oidc_token_body(
            self._auth.project_id,
            app_id,
            code,
            code_verifier if code_verifier else "",
            client_secret if client_secret else "",
            redirect_uri if redirect_uri else "",
        )
        response = await self._http._async_execute_with_retry(
            lambda: self._http._async_client.post(
                f"{self._http.base_url}/oauth2/v1/{self._auth.project_id}/token",
                data=body,
                follow_redirects=False,
            )
        )
        self._http._raise_from_response(response)
        return response.json()
