from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
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

        if not identifier:
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        uri = EndpointsV1.signUpAuthTOTPPath
        body = TOTP._compose_signup_body(identifier, user)
        response = self._auth_helper.do_post(uri, body)

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

        if not identifier:
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        if not code:
            raise AuthException(500, "Invalid argument", "Code cannot be empty")

        uri = EndpointsV1.verifyTOTPPath
        body = TOTP._compose_signin_body(identifier, code)
        response = self._auth_helper.do_post(uri, body)

        resp = response.json()
        jwt_response = self._auth_helper._generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def update_user(self, identifier: str, refresh_token: str) -> None:
        """
        Docs
        """

        if not identifier:
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        if not refresh_token:
            raise AuthException(500, "Invalid argument", "Refresh token cannot be empty")

        uri = EndpointsV1.updateTOTPPath
        body = TOTP._compose_update_user_body(identifier)
        response = self._auth_helper.do_post(uri, body, None, refresh_token)

        return response.json()
        # Response should have these schema:
        # string provisioningURL = 1;
        # string image = 2;
        # string key = 3;
        # string error = 4;
        
    @staticmethod
    def _compose_signup_body(identifier: str, user: dict) -> dict:
        body = { "externalId": identifier }
        if user is not None:
            body["user"] = user
        return body

    @staticmethod
    def _compose_signin_body(identifier: str, code: str) -> dict:
        return { "externalId": identifier,
                 "code": code
         }

    @staticmethod
    def _compose_update_user_body(identifier: str) -> dict:
        return { "externalId": identifier }