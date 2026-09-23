# This is not part of the public API but a code helper
from __future__ import annotations

import hashlib
import secrets
from base64 import b64encode as base64encode
from base64 import urlsafe_b64encode
from typing import Dict, Optional
from urllib.parse import urlencode

from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class AppBase:
    """Shared, I/O-free base for the Federated App auth-method classes.

    Holds only static validation guards and URL/param composers — no network I/O, no
    ``__init__``.  The two concrete subclasses add the network layer (used only by
    ``exchange_token``):

    - ``App(AppBase, AuthMethodBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``AppAsync(AppBase, AsyncAuthMethodBase)`` — async, uses ``self._http`` (``HTTPClientAsync``)

    A "Federated App" is configured in the Descope Console and represents a
    homegrown/third-party application that delegates its sign-in flow to Descope, with
    Descope acting as the IDP - a real OAuth2 authorize/token pair, confirmed live against a
    real project's ".well-known/openid-configuration": ``/oauth2/v1/{project_id}/authorize``
    and ``/oauth2/v1/{project_id}/token``, with ``client_id`` set to the app's dedicated OIDC
    client ID: ``base64(f"{project_id}:{app_id}")``, padded with trailing ``#``/``##`` so the
    encoding needs no ``=`` (verified byte-for-byte against a live console-issued
    ``clientId``; see ``_build_oidc_client_id``).

    ``start`` never calls the network: the authorize endpoint 303-redirects rather than
    returning JSON, so this just builds that URL (and a fresh PKCE pair) locally and hands it
    back for you to redirect the browser to.

    ``flow`` picks which Descope Flow the login page runs, overriding the app's console
    default (confirmed live: passing an explicit ``flow`` value changes the login page's own
    ``flow`` query param accordingly). This is how to build a "homegrown first factor,
    Descope for MFA only" integration: your own backend handles the first factor, then calls
    ``start`` with ``flow`` set to whatever your own MFA-only flow's ID is (or leave it unset
    if the app's console-configured default flow is already that MFA flow), and
    ``login_hint`` set to the already-identified user - confirmed live to arrive at the login
    page as ``oidc_login_hint``. There is no session-based shortcut available here: OIDC's
    other step-up mechanism (an ``su`` claim carried on Descope's own short-lived "DS"
    session cookie, forwarded via ``oidc-su-session``) requires the browser to already hold a
    Descope-issued session from some prior Descope-native auth - it doesn't apply when the
    first factor never touches Descope at all, which is exactly this case.

    CONFIRMED LIVE, full round trip, against a real confidential-client test app
    (project P3I9XNBUps4jHk4ybbaezDSu7mjH, app SA3I9XPZkJYkcCwN34D77fNpGL1D9): ``start``'s
    URL 303-redirected to Descope's hosted login page with the expected ``sso_app_id``; after
    completing that login (twice - once against the default flow, once against a
    console-edited magic-link MFA flow) and pasting back the resulting ``code``,
    ``exchange_token`` (with both ``code_verifier`` and ``client_secret`` supplied) returned
    real ``access_token``/``refresh_token``/``id_token`` JWTs with `expires_in: 600`. So for a
    confidential client, PKCE + client_secret together are accepted (the client_secret is
    what's actually required for this client type; PKCE was extra and harmless). Passing a
    ``client_secret`` on a public client, or omitting it on a confidential one, is not yet
    tested. Also not yet tested: redirect_uri validation (an unregistered redirect_uri did
    not block the initial authorize redirect in testing, which suggests it's checked later,
    right before the post-login redirect back - not confirmed).

    One thing is still defaulted rather than known per-app up front: whether a *given* app
    requires PKCE (public client) vs a client secret (confidential) vs either (unspecified) -
    ``app_id`` alone doesn't say which, so ``start`` always generates a PKCE pair regardless
    (confirmed harmless above for a confidential app); pass the resulting ``code_verifier``
    through to ``exchange_token`` either way, and add ``client_secret`` if the app turns out
    to be confidential. The discovery doc lists both ``client_secret_basic`` and
    ``client_secret_post`` as supported; this SDK uses the latter (secret in the POST body,
    not a Basic auth header) - the live test above confirms that choice works.
    """

    @staticmethod
    def _validate_app_id(app_id: Optional[str]) -> None:
        if not app_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "App ID cannot be empty")

    @staticmethod
    def _validate_return_url(return_url: Optional[str]) -> None:
        if not return_url:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "return_url is required (it must match a redirect URI registered on the app "
                "in the Descope Console)",
            )

    @staticmethod
    def _generate_random_token(nbytes: int = 32) -> str:
        return secrets.token_urlsafe(nbytes)

    @staticmethod
    def _generate_pkce_pair() -> tuple:
        """Returns (code_verifier, code_challenge) - RFC 7636, S256 method."""
        code_verifier = secrets.token_urlsafe(64)[:128]
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return code_verifier, code_challenge

    @staticmethod
    def _build_oidc_client_id(project_id: str, app_id: str) -> str:
        """Replicates the backend's ``BuildApplicationClientID`` - verified to reproduce a
        real console-issued ``clientId`` byte-for-byte. Standard (not URL-safe) base64,
        padded with ``#``/``##`` before encoding so the output needs no ``=``."""
        raw = f"{project_id}:{app_id}"
        pad = {1: "##", 2: "#"}.get(len(raw) % 3, "")
        return base64encode((raw + pad).encode("ascii")).decode("ascii")

    @staticmethod
    def _compose_oidc_authorize_url(
        base_url: str,
        project_id: str,
        app_id: str,
        return_url: str,
        tenant: str,
        login_hint: str,
        scope: str,
        state: str,
        code_challenge: str,
        flow: str,
    ) -> str:
        params: Dict[str, str] = {
            "response_type": "code",
            "client_id": AppBase._build_oidc_client_id(project_id, app_id),
            "redirect_uri": return_url,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if tenant:
            params["tenant"] = tenant
        if login_hint:
            params["login_hint"] = login_hint
        if flow:
            params["flow"] = flow
        return f"{base_url}/oauth2/v1/{project_id}/authorize?{urlencode(params)}"

    @staticmethod
    def _compose_oidc_token_body(
        project_id: str,
        app_id: str,
        code: str,
        code_verifier: str,
        client_secret: str,
        redirect_uri: str,
    ) -> Dict[str, str]:
        body: Dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": AppBase._build_oidc_client_id(project_id, app_id),
        }
        if code_verifier:
            body["code_verifier"] = code_verifier
        if client_secret:
            body["client_secret"] = client_secret
        if redirect_uri:
            body["redirect_uri"] = redirect_uri
        return body
