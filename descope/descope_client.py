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
            return {SESSION_TOKEN_NAME: res}

    def logout(self, refresh_token: str) -> requests.Response:
        """
        Logout user from all active devices and revoke the refresh_token. After calling this function,
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
        return self._auth.do_get(uri, None, None, refresh_token)

    def refresh_token(self, refresh_token: str) -> dict:
        return self._auth.refresh_token(refresh_token)
