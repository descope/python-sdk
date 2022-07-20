import base64
import json
import os
import re
from threading import Lock
from typing import Tuple

import jwt
from pytest import param
import requests
from email_validator import EmailNotValidError, validate_email
from jwt.exceptions import ExpiredSignatureError
from requests.cookies import RequestsCookieJar  # noqa: F401
from requests.models import Response
from descope.authhelper import AuthHelper  # noqa: F401

from descope.authmethod.magiclink import MagicLink  # noqa: F401
from descope.authmethod.otp import OTP  # noqa: F401
from descope.authmethod.totp import TOTP  # noqa: F401
from descope.authmethod.saml import SAML  # noqa: F401
from descope.authmethod.oauth import OAuth  # noqa: F401
from descope.authmethod.webauthn import WebauthN  # noqa: F401

from descope.common import (
    DEFAULT_BASE_URI,
    DEFAULT_FETCH_PUBLIC_KEY_URI,
    PHONE_REGEX,
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
    OAuthProviders,
)
from descope.exceptions import AuthException


class AuthClient:
    ALGORITHM_KEY = "alg"

    def __init__(self, project_id: str, public_key: str = None):
        auth_helper = AuthHelper(project_id, public_key)
        self._auth_helper = auth_helper
        self._magiclink = MagicLink(auth_helper)
        self._otp = OTP(auth_helper)
        self._totp = TOTP(auth_helper)
        self._oauth = OAuth(auth_helper)
        self._saml = SAML(auth_helper)
        self._webauthn = WebauthN(auth_helper)
    
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


    @staticmethod
    def _compose_refresh_token_url() -> str:
        return EndpointsV1.refreshTokenPath

    @staticmethod
    def _compose_logout_url() -> str:
        return EndpointsV1.logoutPath

    @staticmethod
    def _get_identifier_by_method(
        method: DeliveryMethod, user: dict
    ) -> Tuple[str, str]:
        if method is DeliveryMethod.EMAIL:
            email = user.get("email", "")
            return "email", email
        elif method is DeliveryMethod.PHONE:
            phone = user.get("phone", "")
            return "phone", phone
        elif method is DeliveryMethod.WHATSAPP:
            whatsapp = user.get("phone", "")
            return ("whatsapp", whatsapp)
        else:
            raise AuthException(
                500, "identifier failure", f"Unknown delivery method {method}"
            )

    def refresh_token(self, signed_token: str, signed_refresh_token: str) -> dict:
        cookies = {
            SESSION_COOKIE_NAME: signed_token,
            REFRESH_SESSION_COOKIE_NAME: signed_refresh_token,
        }

        uri = AuthClient._compose_refresh_token_url()
        response = self._auth_helper.do_post(uri, None, cookies)

        resp = response.json()
        auth_info = self._generate_auth_info(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return auth_info

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
        token_claims = self._auth_helper._validate_and_load_tokens(
            signed_token, signed_refresh_token
        )
        return {token_claims["cookieName"]: token_claims}

    def logout(
        self, signed_token: str, signed_refresh_token: str
    ) -> requests.cookies.RequestsCookieJar:

        if signed_token is None or signed_refresh_token is None:
            raise AuthException(
                401,
                "token validation failure",
                f"signed token {signed_token} or/and signed refresh token {signed_refresh_token} are empty",
            )

        uri = AuthClient._compose_logout_url()
        cookies = {
            SESSION_COOKIE_NAME: signed_token,
            REFRESH_SESSION_COOKIE_NAME: signed_refresh_token,
        }

        response = self._auth_helper.do_get(uri, cookies)
        return response.cookies
    