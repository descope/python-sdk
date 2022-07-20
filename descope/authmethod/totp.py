import requests
import json
import re

from email_validator import EmailNotValidError, validate_email

from descope.common import (
    DEFAULT_BASE_URI,
    DEFAULT_FETCH_PUBLIC_KEY_URI,
    PHONE_REGEX,
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
)
from descope.exceptions import AuthException
from descope.authhelper import AuthHelper

class TOTP():
    _auth_helper: AuthHelper

    def __init__(self, auth_helper):
        self._auth_helper = auth_helper
    
    def sign_up(
        self, identifier: str, user: dict = None
    ) -> dict:
        """
        Docs
        """

        if identifier == "":
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        body = {"externalId": identifier}

        if user is not None:
            body["user"] = user

        uri = f"{DEFAULT_BASE_URI}{EndpointsV1.signUpAuthTOTPPath}"
        response = requests.post(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self.client._get_default_headers(),
            data=json.dumps(body),
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.reason)

        return response.json()
        # Response should have these schema:
        # string provisioningURL = 1;
        # string image = 2;
        # string key = 3;
        # string error = 4;

    def sign_in_code(self, identifier: str, code: str) -> dict:
        """
        Docs
        """

        if identifier == "":
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        body = {"externalId": identifier,
                "code": code}


        uri = f"{DEFAULT_BASE_URI}{EndpointsV1.verifyTOTPPath}"
        response = requests.post(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self.client._get_default_headers(),
            data=json.dumps(body),
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.reason)

        resp = response.json()
        jwt_response = self._generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    #UpdateUserTOTP
    def update_user(self, identifier: str, refresh_token: str) -> None:
        """
        Docs
        """

        if identifier == "":
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        body = {"externalId": identifier}


        uri = f"{DEFAULT_BASE_URI}{EndpointsV1.verifyTOTPPath}"
        response = requests.post(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self.client._get_default_headers(refresh_token),
            data=json.dumps(body),
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.reason)

        return response.json()
        # Response should have these schema:
        # string provisioningURL = 1;
        # string image = 2;
        # string key = 3;
        # string error = 4;