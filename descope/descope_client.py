from __future__ import annotations

import os
from typing import Iterable, Optional

import requests

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
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.http_client import HTTPClient
from descope.mgmt import MGMT  # noqa: F401


class DescopeClient:
    ALGORITHM_KEY = "alg"

    def __init__(
        self,
        project_id: str,
        public_key: Optional[dict] = None,
        skip_verify: bool = False,
        management_key: Optional[str] = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        jwt_validation_leeway: int = 5,
        auth_management_key: Optional[str] = None,
        fga_cache_url: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
    ):
        # validate project id
        project_id = project_id or os.getenv("DESCOPE_PROJECT_ID", "")
        if not project_id:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                (
                    "Unable to init DescopeClient because project_id cannot be empty. "
                    "Set environment variable DESCOPE_PROJECT_ID or pass your Project ID to the init function."
                ),
            )

        # Auth Initialization
        auth_http_client = HTTPClient(
            project_id=project_id,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            secure=not skip_verify,
            management_key=auth_management_key
            or os.getenv("DESCOPE_AUTH_MANAGEMENT_KEY"),
        )
        self._auth = Auth(
            project_id,
            public_key,
            jwt_validation_leeway,
            http_client=auth_http_client,
        )
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
        )
        self._mgmt = MGMT(
            http_client=mgmt_http_client,
            auth=self._auth,
            fga_cache_url=fga_cache_url,
        )

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

    def validate_permissions(self, jwt_response: dict, permissions: list[str]) -> bool:
        """
        Validate that a jwt_response has been granted the specified permissions.
            For a multi-tenant environment use validate_tenant_permissions function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        permissions (List[str]): List of permissions to validate for this jwt_response

        Return value (bool): returns true if all permissions granted; false if at least one permission not granted
        """
        return self.validate_tenant_permissions(jwt_response, "", permissions)

    def get_matched_permissions(
        self, jwt_response: dict, permissions: list[str]
    ) -> list[str]:
        """
        Get the list of permissions that a jwt_response has been granted from the provided list of permissions.
            For a multi-tenant environment use get_matched_tenant_permissions function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        permissions (List[str]): List of permissions to validate for this jwt_response

        Return value (List[str]): returns the list of permissions that are granted
        """
        return self.get_matched_tenant_permissions(jwt_response, "", permissions)

    def validate_tenant_permissions(
        self, jwt_response: dict, tenant: str, permissions: list[str]
    ) -> bool:
        """
        Validate that a jwt_response has been granted the specified permissions on the specified tenant.
            For a multi-tenant environment use validate_tenant_permissions function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        tenant (str): TenantId
        permissions (List[str]): List of permissions to validate for this jwt_response

        Return value (bool): returns true if all permissions granted; false if at least one permission not granted
        """
        if not jwt_response:
            return False

        if isinstance(permissions, str):
            permissions = [permissions]

        granted = []
        if tenant == "":
            granted = jwt_response.get("permissions", [])
        else:
            # ensure that the tenant is associated with the jwt_response
            if tenant not in jwt_response.get("tenants", {}):
                return False
            granted = (
                jwt_response.get("tenants", {}).get(tenant, {}).get("permissions", [])
            )

        for perm in permissions:
            if perm not in granted:
                return False
        return True

    def get_matched_tenant_permissions(
        self, jwt_response: dict, tenant: str, permissions: list[str]
    ) -> list[str]:
        """
        Get the list of permissions that a jwt_response has been granted from the provided list of permissions on the specified tenant.
            For a multi-tenant environment use get_matched_tenant_permissions function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        tenant (str): TenantId
        permissions (List[str]): List of permissions to validate for this jwt_response

        Return value (List[str]): returns the list of permissions that are granted
        """
        if not jwt_response:
            return []

        if isinstance(permissions, str):
            permissions = [permissions]

        granted = []
        if tenant == "":
            granted = jwt_response.get("permissions", [])
        else:
            # ensure that the tenant is associated with the jwt_response
            if tenant not in jwt_response.get("tenants", {}):
                return []
            granted = (
                jwt_response.get("tenants", {}).get(tenant, {}).get("permissions", [])
            )

        matched = []
        for perm in permissions:
            if perm in granted:
                matched.append(perm)
        return matched

    def validate_roles(self, jwt_response: dict, roles: list[str]) -> bool:
        """
        Validate that a jwt_response has been granted the specified roles.
            For a multi-tenant environment use validate_tenant_roles function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        roles (List[str]): List of roles to validate for this jwt_response

        Return value (bool): returns true if all roles granted; false if at least one role not granted
        """
        return self.validate_tenant_roles(jwt_response, "", roles)

    def get_matched_roles(self, jwt_response: dict, roles: list[str]) -> list[str]:
        """
        Get the list of roles that a jwt_response has been granted from the provided list of roles.
            For a multi-tenant environment use get_matched_tenant_roles function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        roles (List[str]): List of roles to validate for this jwt_response

        Return value (List[str]): returns the list of roles that are granted
        """
        return self.get_matched_tenant_roles(jwt_response, "", roles)

    def validate_tenant_roles(
        self, jwt_response: dict, tenant: str, roles: list[str]
    ) -> bool:
        """
        Validate that a jwt_response has been granted the specified roles on the specified tenant.
            For a multi-tenant environment use validate_tenant_roles function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        tenant (str): TenantId
        roles (List[str]): List of roles to validate for this jwt_response

        Return value (bool): returns true if all roles granted; false if at least one role not granted
        """
        if not jwt_response:
            return False

        if isinstance(roles, str):
            roles = [roles]

        granted = []
        if tenant == "":
            granted = jwt_response.get("roles", [])
        else:
            # ensure that the tenant is associated with the jwt_response
            if tenant not in jwt_response.get("tenants", {}):
                return False
            granted = jwt_response.get("tenants", {}).get(tenant, {}).get("roles", [])

        for role in roles:
            if role not in granted:
                return False
        return True

    def get_matched_tenant_roles(
        self, jwt_response: dict, tenant: str, roles: list[str]
    ) -> list[str]:
        """
        Get the list of roles that a jwt_response has been granted from the provided list of roles on the specified tenant.
            For a multi-tenant environment use get_matched_tenant_roles function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        tenant (str): TenantId
        roles (List[str]): List of roles to validate for this jwt_response

        Return value (List[str]): returns the list of roles that are granted
        """
        if not jwt_response:
            return []

        if isinstance(roles, str):
            roles = [roles]

        granted = []
        if tenant == "":
            granted = jwt_response.get("roles", [])
        else:
            # ensure that the tenant is associated with the jwt_response
            if tenant not in jwt_response.get("tenants", {}):
                return []
            granted = jwt_response.get("tenants", {}).get(tenant, {}).get("roles", [])

        matched = []
        for role in roles:
            if role in granted:
                matched.append(role)
        return matched

    def validate_session(
        self, session_token: str, audience: Optional[Iterable[str] | str] = None
    ) -> dict:
        """
        Validate a session token. Call this function for every incoming request to your
        private endpoints. Alternatively, use validate_and_refresh_session in order to
        automatically refresh expired sessions. If you need to use these specific claims
        [amr, drn, exp, iss, rexp, sub, jwt] in the top level of the response dict, please use
        them from the sessionToken key instead, as these claims will soon be deprecated from the top level
        of the response dict.

        Args:
        session_token (str): The session token to be validated
        audience (str|Iterable[str]|None): Optional recipients that the JWT is intended for (must be equal to the 'aud' claim on the provided token)

        Return value (dict):
        Return dict includes the session token and all JWT claims

        Raise:
        AuthException: Exception is raised if session is not authorized or any other error occurs
        """
        return self._auth.validate_session(session_token, audience)

    def refresh_session(
        self, refresh_token: str, audience: Optional[Iterable[str] | str] = None
    ) -> dict:
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
        audience: Optional[Iterable[str] | str] = None,
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
        return self._auth.validate_and_refresh_session(
            session_token, refresh_token, audience
        )

    def logout(self, refresh_token: str) -> requests.Response:
        """
        Logout user from current session and revoke the refresh_token. After calling this function,
            you must invalidate or remove any cookies you have created.

        Args:
        refresh_token (str): The refresh token

        Return value (requests.Response): returns the response from the Descope server

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        if refresh_token is None:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"signed refresh token {refresh_token} is empty",
            )

        uri = EndpointsV1.logout_path
        return self._auth.http_client.post(uri, body={}, pswd=refresh_token)

    def logout_all(self, refresh_token: str) -> requests.Response:
        """
        Logout user from all active sessions and revoke the refresh_token. After calling this function,
            you must invalidate or remove any cookies you have created.

        Args:
        refresh_token (str): The refresh token

        Return value (requests.Response): returns the response from the Descope server

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        if refresh_token is None:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"signed refresh token {refresh_token} is empty",
            )

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
        if refresh_token is None:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"signed refresh token {refresh_token} is empty",
            )

        uri = EndpointsV1.me_path
        response = self._auth.http_client.get(
            uri=uri, allow_redirects=None, pswd=refresh_token
        )
        return response.json()

    def my_tenants(
        self,
        refresh_token: str,
        dct: bool = False,
        ids: Optional[list[str]] = None,
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
        if refresh_token is None:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"signed refresh token {refresh_token} is empty",
            )
        if dct is True and ids is not None and len(ids) > 0:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "Only one of 'dct' or 'ids' should be supplied",
            )
        if dct is False and (ids is None or len(ids) == 0):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "Only one of 'dct' or 'ids' should be supplied",
            )

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
        if refresh_token is None:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"signed refresh token {refresh_token} is empty",
            )

        uri = EndpointsV1.history_path
        response = self._auth.http_client.get(
            uri=uri, allow_redirects=None, pswd=refresh_token
        )
        return response.json()

    def exchange_access_key(
        self,
        access_key: str,
        audience: Optional[Iterable[str] | str] = None,
        login_options: Optional[AccessKeyLoginOptions] = None,
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
        if not access_key:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Access key cannot be empty"
            )

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
