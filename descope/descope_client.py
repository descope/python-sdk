import requests

from descope.auth import Auth  # noqa: F401
from descope.authmethod.magiclink import MagicLink  # noqa: F401
from descope.authmethod.oauth import OAuth  # noqa: F401
from descope.authmethod.otp import OTP  # noqa: F401
from descope.authmethod.saml import SAML  # noqa: F401
from descope.authmethod.totp import TOTP  # noqa: F401
from descope.authmethod.webauthn import WebauthN  # noqa: F401
from descope.common import SESSION_TOKEN_NAME, EndpointsV1
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class DescopeClient:
    ALGORITHM_KEY = "alg"

    def __init__(
        self,
        project_id: str = None,
        public_key: str = None,
        skip_verify: bool = False,
    ):
        auth = Auth(project_id, public_key, skip_verify)
        self._auth = auth
        self._magiclink = MagicLink(auth)
        self._oauth = OAuth(auth)
        self._saml = SAML(auth)
        self._otp = OTP(auth)
        self._totp = TOTP(auth)
        self._webauthn = WebauthN(auth)

    @property
    def magiclink(self):
        return self._magiclink

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

    def validate_permissions(self, jwt_response: dict, permissions: list[str]) -> bool:
        """
        Validate that a jwt_response has been granted the specified permissions.
            For a multi-tenant environment use validate_tenant_permissions function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        permissions (list[str]): List of permissions to validate for this jwt_response

        Return value (bool): returns true if all permissions granted; false if at least one permission not granted
        """
        return self.validate_tenant_permissions(jwt_response, "", permissions)

    def validate_tenant_permissions(
        self, jwt_response: dict, tenant: str, permissions: list[str]
    ) -> bool:
        """
        Validate that a jwt_response has been granted the specified permissions on the specified tenant.
            For a multi-tenant environment use validate_tenant_permissions function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        tenant (str): TenantId
        permissions (list[str]): List of permissions to validate for this jwt_response

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

    def validate_roles(self, jwt_response: dict, roles: list[str]) -> bool:
        """
        Validate that a jwt_response has been granted the specified roles.
            For a multi-tenant environment use validate_tenant_roles function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        roles (list[str]): List of roles to validate for this jwt_response

        Return value (bool): returns true if all roles granted; false if at least one role not granted
        """
        return self.validate_tenant_roles(jwt_response, "", roles)

    def validate_tenant_roles(
        self, jwt_response: dict, tenant: str, roles: list[str]
    ) -> bool:
        """
        Validate that a jwt_response has been granted the specified roles on the specified tenant.
            For a multi-tenant environment use validate_tenant_roles function

        Args:
        jwt_response (dict): The jwt_response object which includes all JWT claims information
        tenant (str): TenantId
        roles (list[str]): List of roles to validate for this jwt_response

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

    def validate_session_request(self, session_token: str, refresh_token: str) -> dict:
        """
        Validate the session for a given request. If the user is authenticated but the
            session has expired, the session token will automatically be refreshed.
        Either the session_token or the refresh_token must be provided.
        Call this function every time you make a private API call that requires an authorized
            user.

        Args:
        session_token (str): The session token, which contains the signature that will be validated
        refresh_token (str): The refresh token that will be used to refresh the session token, if needed

        Return value (dict):
        Return dict includes the session token, refresh token, and all JWT claims

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        res = self._auth._validate_and_load_tokens(
            session_token, refresh_token
        )  # return jwt_response dict

        # Check if we had to refresh the session token and got a new one
        if res.get(SESSION_TOKEN_NAME, None) and session_token != res.get(
            SESSION_TOKEN_NAME
        ).get("jwt"):
            return res
        else:
            # In such case we return only the data related to the session token
            return self._auth.adjust_properties({SESSION_TOKEN_NAME: res})

    def logout(self, refresh_token: str) -> requests.Response:
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

        uri = EndpointsV1.logoutPath
        return self._auth.do_post(uri, {}, refresh_token)

    def me(self, refresh_token: str) -> dict:
        """
        Retrieve user details for the refresh token. The returned data includes email, name, phone,
            list of externalIds and boolean flags for verifiedEmail, verifiedPhone.

        Args:
        refresh_token (str): The refresh token

        Return value (dict): returns the user details from the server
            (email:str, name:str, phone:str, externalIds[str], verifiedEmail:bool, verifiedPhone:bool)

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        if refresh_token is None:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"signed refresh token {refresh_token} is empty",
            )

        uri = EndpointsV1.mePath
        response = self._auth.do_get(uri, None, None, refresh_token)
        return response.json()

    def refresh_token(self, refresh_token: str) -> dict:
        """
        Return a new session token for the given refresh token

        Args:
        refresh_token (str): The refresh token

        Return value (dict): returns the session token from the server

        Raise:
        AuthException: Exception is raised if session is not authorized or another error occurs
        """
        return self._auth.refresh_token(refresh_token)

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
