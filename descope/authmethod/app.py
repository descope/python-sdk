from __future__ import annotations

from typing import Optional

import httpx

from descope._authmethod_base import AuthMethodBase
from descope.authmethod._app_base import AppBase
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class App(AppBase, AuthMethodBase):
    def start(
        self,
        app_id: str,
        return_url: str,
        tenant: Optional[str] = None,
        login_hint: Optional[str] = None,
        scope: Optional[str] = None,
        state: Optional[str] = None,
        flow: Optional[str] = None,
    ) -> dict:
        """
        Build the sign-in redirect URL for an OIDC Federated App.

        This makes no network call: the authorize endpoint 303-redirects rather than
        returning JSON, so this just builds the URL (and a fresh PKCE pair) locally. See
        ``AppBase`` for the full explanation and the live round-trip confirmation.

        Args:
            app_id (str): The Federated App ID (as configured in the Descope Console)
            return_url (str): Must match a redirect URI registered on the app in the console.
            tenant (str, optional): Tenant ID or name, for apps scoped to a specific tenant
            login_hint (str, optional): Hint about the user's login identifier
            scope (str, optional): Defaults to "openid"
            state (str, optional): Defaults to a generated random value (returned back to you
                either way, so you can verify it on the callback)
            flow (str, optional): Which Descope Flow the login page runs, overriding the
                app's console default. Use this for a "homegrown first factor, Descope for
                MFA only" integration: pass your own MFA-only flow's ID along with
                ``login_hint`` set to the already-identified user - confirmed live to reach
                the login page as ``oidc_login_hint``. Leave unset if the app's console
                default flow is already the MFA flow you want. See ``AppBase`` for why the
                session-cookie-based step-up shortcut doesn't apply when the first factor
                never touches Descope.

        Return value (dict): ``{'url': ..., 'state': ..., 'code_verifier': ...}`` - hold onto
        ``state`` and ``code_verifier`` and pass them to ``exchange_token``.
        """
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

    def exchange_token(
        self,
        app_id: str,
        code: str,
        code_verifier: Optional[str] = None,
        client_secret: Optional[str] = None,
        redirect_uri: Optional[str] = None,
    ) -> dict:
        """
        Exchange a Federated App authorization code for tokens.

        CONFIRMED LIVE end-to-end: a real login through the URL from ``start``, followed by
        this call with the resulting code, code_verifier, and the app's client_secret,
        returned real access/refresh/ID tokens (see ``AppBase`` for the details). This
        deliberately bypasses the SDK's default headers/JSON body - the token endpoint is a
        standard OAuth2 endpoint (form-encoded body, client credentials in the body, no
        Descope bearer header), confirmed working via ``client_secret_post`` (secret in the
        body, per the project's discovery document). Retries and rate-limit handling still go
        through the shared HTTP client.

        Args:
            app_id (str): The Federated App ID passed to ``start``
            code (str): The authorization code from the redirect callback
            code_verifier (str, optional): The value ``start`` returned - pass it even for a
                confidential app (harmless extra; confirmed live alongside client_secret)
            client_secret (str, optional): Required if the app is a confidential client
            redirect_uri (str, optional): Must match the return_url passed to ``start``

        Returns dict in the raw OAuth2/OIDC token shape (access_token, token_type,
        refresh_token, id_token, expires_in, scope) - not this SDK's usual session shape.
        """
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
        response = self._http._execute_with_retry(
            lambda: httpx.post(
                f"{self._http.base_url}/oauth2/v1/{self._auth.project_id}/token",
                data=body,
                follow_redirects=False,
                verify=self._http.client_verify,
                timeout=self._http.timeout_seconds,
            )
        )
        self._http._raise_from_response(response)
        return response.json()
