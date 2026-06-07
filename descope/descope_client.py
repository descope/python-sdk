from __future__ import annotations

import logging
import os
from typing import Iterable

import httpx

from descope._client_base import DescopeClientBase
from descope.auth import Auth  # noqa: F401
from descope.authmethod.enchantedlink import EnchantedLink  # noqa: F401
from descope.authmethod.magiclink import MagicLink  # noqa: F401
from descope.authmethod.oauth import OAuth  # noqa: F401
from descope.authmethod.otp import OTP  # noqa: F401
from descope.authmethod.password import Password  # noqa: F401
from descope.authmethod.saml import SAML  # noqa: F401
from descope.authmethod.sso import SSO  # noqa: F401
from descope.authmethod.totp import TOTP  # noqa: F401
from descope.authmethod.webauthn import WebAuthn  # noqa: F401
from descope.common import DEFAULT_TIMEOUT_SECONDS, AccessKeyLoginOptions, EndpointsV1
from descope.http_client import HTTPClient
from descope.mgmt import MGMT  # noqa: F401

logger = logging.getLogger(__name__)


class DescopeClient(DescopeClientBase):
    ALGORITHM_KEY = "alg"

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
        auth_http_client = self._auth.http_client

        self._magiclink = MagicLink(self._auth)
        self._enchantedlink = EnchantedLink(self._auth)
        self._oauth = OAuth(self._auth)
        self._saml = SAML(self._auth)  # deprecated
        self._sso = SSO(self._auth)
        self._otp = OTP(self._auth)
        self._totp = TOTP(self._auth)
        self._webauthn = WebAuthn(self._auth)
        self._password = Password(self._auth)

        # Management Initialization
        mgmt_http_client = HTTPClient(
            project_id=project_id,
            base_url=auth_http_client.base_url,
            timeout_seconds=auth_http_client.timeout_seconds,
            secure=auth_http_client.secure,
            management_key=management_key or os.getenv("DESCOPE_MANAGEMENT_KEY"),
            verbose=verbose,
        )
        self._mgmt = MGMT(
            http_client=mgmt_http_client,
            auth=self._auth,
            fga_cache_url=fga_cache_url,
        )

        # Store references to HTTP clients for verbose mode access
        self._auth_http_client = auth_http_client
        self._mgmt_http_client = mgmt_http_client

        # Synchronous license handshake so the first management request after
        # construction can carry the x-descope-license header. Backend skips
        # license-header validation for the GetLicense endpoint itself, so the
        # initial request is safe before the tier is cached.
        if mgmt_http_client.management_key:
            self._fetch_rate_limit_tier(mgmt_http_client)

    @property
    def mgmt(self):
        return self._mgmt

    @property
    def magiclink(self):
        return self._magiclink

    @property
    def enchantedlink(self):
        return self._enchantedlink

    @property
    def otp(self):
        return self._otp

    @property
    def totp(self):
        return self._totp

    @property
    def oauth(self):
        return self._oauth

    # ######## deprecated (use sso instead)
    @property
    def saml(self):
        return self._saml

    # ###################

    @property
    def sso(self):
        return self._sso

    @property
    def webauthn(self):
        return self._webauthn

    @property
    def password(self):
        return self._password

    def refresh_session(self, refresh_token: str, audience: Iterable[str] | str | None = None) -> dict:
        """
        Refresh a session. Call this function when a session expires and needs to be refreshed.

        Args:
        refresh_token (str): The refresh token that will be used to refresh the session
        audience (str|Iterable[str]|None): Optional recipients that the JWT is intended for (must be equal to the 'aud' claim on the provided token)

        Return value (dict):
        Return dict includes the session token, refresh token, and all JWT claims

        Raise:
        AuthException: Exception is raised if refresh token is not authorized or any other error occurs
        """
        return self._auth.refresh_session(refresh_token, audience)

    def validate_and_refresh_session(
        self,
        session_token: str,
        refresh_token: str,
        audience: Iterable[str] | str | None = None,
    ) -> dict:
        """
        Validate the session token and refresh it if it has expired, the session token will automatically be refreshed.
        Either the session_token or the refresh_token must be provided.
        Call this function for every incoming request to your
        private endpoints. Alternatively, use validate_session to only validate the session.

        Args:
        session_token (str): The session token to be validated
        refresh_token (str): The refresh token that will be used to refresh the session token, if needed
        audience (str|Iterable[str]|None): Optional recipients that the JWT is intended for (must be equal to the 'aud' claim on the provided token)

        Return value (dict):
        Return dict includes the session token, refresh token, and all JWT claims

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        return self._auth.validate_and_refresh_session(session_token, refresh_token, audience)

    def logout(self, refresh_token: str) -> httpx.Response:
        """
        Logout user from current session and revoke the refresh_token. After calling this function,
            you must invalidate or remove any cookies you have created.

        Args:
        refresh_token (str): The refresh token

        Return value (httpx.Response): returns the response from the Descope server

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        self._require_refresh_token(refresh_token)
        uri = EndpointsV1.logout_path
        return self._auth.http_client.post(uri, body={}, pswd=refresh_token)

    def logout_all(self, refresh_token: str) -> httpx.Response:
        """
        Logout user from all active sessions and revoke the refresh_token. After calling this function,
            you must invalidate or remove any cookies you have created.

        Args:
        refresh_token (str): The refresh token

        Return value (httpx.Response): returns the response from the Descope server

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        self._require_refresh_token(refresh_token)
        uri = EndpointsV1.logout_all_path
        return self._auth.http_client.post(uri, body={}, pswd=refresh_token)

    def me(self, refresh_token: str) -> dict:
        """
        Retrieve user details for the refresh token. The returned data includes email, name, phone,
            list of loginIds and boolean flags for verifiedEmail, verifiedPhone.

        Args:
        refresh_token (str): The refresh token

        Return value (dict): returns the user details from the server
            (email:str, name:str, phone:str, loginIds[str], verifiedEmail:bool, verifiedPhone:bool)

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        self._require_refresh_token(refresh_token)
        uri = EndpointsV1.me_path
        response = self._auth.http_client.get(uri=uri, allow_redirects=None, pswd=refresh_token)
        return response.json()

    def my_tenants(
        self,
        refresh_token: str,
        dct: bool = False,
        ids: list[str] | None = None,
    ) -> dict:
        """
        Retrieve tenant attributes that user belongs to, one of dct/ids must be populated .

        Args:
        dct (bool): Get only the selected tenant from jwt
        ids (List[str]): Get the list of tenants
        refresh_token (str): The refresh token

        Return value (dict): returns the tenant requested from the server
            (id:str, name:str, customAttributes:dict)

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        self._require_refresh_token(refresh_token)
        self._validate_tenant_selector(dct, ids)

        body: dict[str, bool | list[str]] = {"dct": dct}
        if ids is not None:
            body["ids"] = ids

        uri = EndpointsV1.my_tenants_path
        response = self._auth.http_client.post(uri, body=body, pswd=refresh_token)
        return response.json()

    def history(self, refresh_token: str) -> list[dict]:
        """
        Retrieve user authentication history for the refresh token

        Args:
        refresh_token (str): The refresh token

        Return value (List[dict]):
        Return List in the format
             [
                {
                    "userId": "User's ID",
                    "loginTime": "User'sLogin time",
                    "city": "User's city",
                    "country": "User's country",
                    "ip": User's IP
                }
            ]

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        self._require_refresh_token(refresh_token)
        uri = EndpointsV1.history_path
        response = self._auth.http_client.get(uri=uri, allow_redirects=None, pswd=refresh_token)
        return response.json()

    def exchange_access_key(
        self,
        access_key: str,
        audience: Iterable[str] | str | None = None,
        login_options: AccessKeyLoginOptions | None = None,
    ) -> dict:
        """
        Return a new session token for the given access key

        Args:
        access_key (str): The access key
        audience (str|Iterable[str]|None): Optional recipients that the JWT is intended for (must be equal to the 'aud' claim on the provided token)
        login_options (AccessKeyLoginOptions): Optional advanced controls over login parameters

        Return dict includes the session token and all JWT claims

        Raise:
        AuthException: Exception is raised if access key is not valid or another error occurs
        """
        self._require_access_key(access_key)
        return self._auth.exchange_access_key(access_key, audience, login_options)

    def select_tenant(
        self,
        tenant_id: str,
        refresh_token: str,
    ) -> dict:
        """
        Add to JWT a selected tenant claim

        Args:
        refresh_token (str): The refresh token that will be used to refresh the session token, if needed
        tenant_id (str): The tenant id to place on JWT

        Return value (dict):
        Return dict includes the session token, refresh token, with the tenant id on the jwt

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        return self._auth.select_tenant(tenant_id, refresh_token)

    def get_last_response(self):
        """
        Get the last HTTP response from either auth or management operations.

        Only available when verbose mode is enabled during client initialization.
        This provides access to HTTP metadata like headers (cf-ray), status codes,
        and raw response data for debugging failed requests.

        Returns:
            DescopeResponse: The last response if verbose mode is enabled.
                           Returns the most recent response from either auth or mgmt operations.
                           None if verbose mode is disabled or no requests have been made.

        Example:
            client = DescopeClient(project_id, management_key, verbose=True)
            try:
                client.mgmt.user.create(login_id="test@example.com")
            except AuthException:
                resp = client.get_last_response()
                if resp:
                    # Access metadata for debugging
                    cf_ray = resp.headers.get("cf-ray")
                    status = resp.status_code
        """
        # Return the most recently used response
        mgmt_resp = self._mgmt_http_client.get_last_response()
        auth_resp = self._auth_http_client.get_last_response()

        # Return whichever is not None, preferring mgmt if both exist
        # (in practice, only one should be non-None at a time)
        return mgmt_resp or auth_resp
