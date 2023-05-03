from typing import List

import requests

from descope.auth import Auth  # noqa: F401
from descope.authmethod.enchantedlink import EnchantedLink  # noqa: F401
from descope.authmethod.magiclink import MagicLink  # noqa: F401
from descope.authmethod.oauth import OAuth  # noqa: F401
from descope.authmethod.otp import OTP  # noqa: F401
from descope.authmethod.password import Password  # noqa: F401
from descope.authmethod.saml import SAML  # noqa: F401
from descope.authmethod.totp import TOTP  # noqa: F401
from descope.authmethod.webauthn import WebAuthn  # noqa: F401
from descope.common import DEFAULT_TIMEOUT_SECONDS, EndpointsV1
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.mgmt import MGMT  # noqa: F401


class DescopeClient:
    ALGORITHM_KEY = "alg"

    def __init__(
        self,
        project_id: str = None,
        public_key: str = None,
        skip_verify: bool = False,
        management_key: str = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        auth = Auth(
            project_id, public_key, skip_verify, management_key, timeout_seconds
        )
        self._auth = auth
        self._mgmt = MGMT(auth)
        self._magiclink = MagicLink(auth)
        self._enchantedlink = EnchantedLink(auth)
        self._oauth = OAuth(auth)
        self._saml = SAML(auth)
        self._otp = OTP(auth)
        self._totp = TOTP(auth)
        self._webauthn = WebAuthn(auth)
        self._password = Password(auth)

    @property
    def mgmt(self):
        if not self._auth.management_key:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "management_key cannot be empty"
            )
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

    @property
    def saml(self):
        return self._saml

    @property
    def webauthn(self):
        return self._webauthn

    @property
    def password(self):
        return self._password

    def validate_permissions(self, jwt_response: dict, permissions: List[str]) -> bool:
        """
        Validate that a jwt_response has been granted the specified permissions.
            For a multi-tenant environment use validate_tenant_permissions function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        permissions (List[str]): List of permissions to validate for this jwt_response

        Return value (bool): returns true if all permissions granted; false if at least one permission not granted
        """
        return self.validate_tenant_permissions(jwt_response, "", permissions)

    def validate_tenant_permissions(
        self, jwt_response: dict, tenant: str, permissions: List[str]
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
            granted = (
                jwt_response.get("tenants", {}).get(tenant, {}).get("permissions", [])
            )

        for perm in permissions:
            if perm not in granted:
                return False
        return True

    def validate_roles(self, jwt_response: dict, roles: List[str]) -> bool:
        """
        Validate that a jwt_response has been granted the specified roles.
            For a multi-tenant environment use validate_tenant_roles function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        roles (List[str]): List of roles to validate for this jwt_response

        Return value (bool): returns true if all roles granted; false if at least one role not granted
        """
        return self.validate_tenant_roles(jwt_response, "", roles)

    def validate_tenant_roles(
        self, jwt_response: dict, tenant: str, roles: List[str]
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
            granted = jwt_response.get("tenants", {}).get(tenant, {}).get("roles", [])

        for role in roles:
            if role not in granted:
                return False
        return True

    def validate_session(self, session_token: str) -> dict:
        """
        Validate a session token. Call this function for every incoming request to your
        private endpoints. Alternatively, use validate_and_refresh_session in order to
        automatically refresh expired sessions.

        Args:
        session_token (str): The session token to be validated

        Return value (dict):
        Return dict includes the session token and all JWT claims

        Raise:
        AuthException: Exception is raised if session is not authorized or any other error occurs
        """
        return self._auth.validate_session(session_token)

    def refresh_session(self, refresh_token: str) -> dict:
        """
        Refresh a session. Call this function when a session expires and needs to be refreshed.

        Args:
        refresh_token (str): The refresh token that will be used to refresh the session

        Return value (dict):
        Return dict includes the session token, refresh token, and all JWT claims

        Raise:
        AuthException: Exception is raised if refresh token is not authorized or any other error occurs
        """
        return self._auth.refresh_session(refresh_token)

    def validate_and_refresh_session(
        self, session_token: str, refresh_token: str
    ) -> dict:
        """
        Validate the session token and refresh it if it has expired, the session token will automatically be refreshed.
        Either the session_token or the refresh_token must be provided.
        Call this function for every incoming request to your
        private endpoints. Alternatively, use validate_session to only validate the session.

        Args:
        session_token (str): The session token to be validated
        refresh_token (str): The refresh token that will be used to refresh the session token, if needed

        Return value (dict):
        Return dict includes the session token, refresh token, and all JWT claims

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        return self._auth.validate_and_refresh_session(session_token, refresh_token)

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
        return self._auth.do_post(uri, {}, None, refresh_token)

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
        return self._auth.do_post(uri, {}, None, refresh_token)

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
        response = self._auth.do_get(uri, None, None, refresh_token)
        return response.json()

    def exchange_access_key(self, access_key: str) -> dict:
        """
        Return a new session token for the given access key

        Args:
        access_key (str): The access key

        Return value (dict): returns the session token from the server together with the expiry and key id
            (sessionToken:dict, keyId:str, expiration:int)

        Raise:
        AuthException: Exception is raised if access key is not valid or another error occurs
        """
        if not access_key:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Access key cannot be empty"
            )

        return self._auth.exchange_access_key(access_key)
