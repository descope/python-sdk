import requests

from descope.auth import Auth  # noqa: F401
from descope.authmethod.exchanger import Exchanger  # noqa: F401
from descope.authmethod.magiclink import MagicLink  # noqa: F401
from descope.authmethod.oauth import OAuth  # noqa: F401
from descope.authmethod.otp import OTP  # noqa: F401
from descope.authmethod.saml import SAML  # noqa: F401
from descope.authmethod.totp import TOTP  # noqa: F401
from descope.authmethod.webauthn import WebauthN  # noqa: F401
from descope.common import EndpointsV1
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class DescopeClient:
    ALGORITHM_KEY = "alg"

    def __init__(self, project_id: str, public_key: str = None):
        auth = Auth(project_id, public_key)
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

    def validate_session_request(
        self, signed_token: str, signed_refresh_token: str
    ) -> dict:
        """
        Validate session request by verify the session JWT session token
        and session refresh token in case it expired

        Args:
        signed_token (str): The session JWT token to get its signature verified

        signed_refresh_token (str): The session refresh JWT token that will be
        use to refresh the session token (if expired)

        Return value (Tuple[dict, dict]):
        Return two dicts where the first contains the jwt claims data and
        second contains the existing signed token (or the new signed
        token in case the old one expired) and refreshed session token

        Raise:
        AuthException: for any case token is not valid means session is not
        authorized
        """
        token_claims = self._auth._validate_and_load_tokens(
            signed_token, signed_refresh_token
        )
        return {token_claims["cookieName"]: token_claims}

    def logout(self, signed_refresh_token: str) -> requests.cookies.RequestsCookieJar:
        if signed_refresh_token is None:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"signed refresh token {signed_refresh_token} is empty",
            )

        uri = EndpointsV1.logoutPath

        response = self._auth.do_get(uri, None, None, None, signed_refresh_token)
        return response.cookies
