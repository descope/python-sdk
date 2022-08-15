from descope.auth import Auth
from descope.common import REFRESH_SESSION_COOKIE_NAME, EndpointsV1
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class TOTP:
    _auth: Auth

    def __init__(self, auth):
        self._auth = auth

    def sign_up(self, identifier: str, user: dict = None) -> dict:
        """
        Docs
        """

        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        uri = EndpointsV1.signUpAuthTOTPPath
        body = TOTP._compose_signup_body(identifier, user)
        response = self._auth.do_post(uri, body)

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
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        if not code:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Code cannot be empty"
            )

        uri = EndpointsV1.verifyTOTPPath
        body = TOTP._compose_signin_body(identifier, code)
        response = self._auth.do_post(uri, body)

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def update_user(self, identifier: str, refresh_token: str) -> None:
        """
        Docs
        """

        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        if not refresh_token:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Refresh token cannot be empty"
            )

        uri = EndpointsV1.updateTOTPPath
        body = TOTP._compose_update_user_body(identifier)
        response = self._auth.do_post(uri, body, refresh_token)

        return response.json()
        # Response should have these schema:
        # string provisioningURL = 1;
        # string image = 2;
        # string key = 3;
        # string error = 4;

    @staticmethod
    def _compose_signup_body(identifier: str, user: dict) -> dict:
        body = {"externalId": identifier}
        if user is not None:
            body["user"] = user
        return body

    @staticmethod
    def _compose_signin_body(identifier: str, code: str) -> dict:
        return {"externalId": identifier, "code": code}

    @staticmethod
    def _compose_update_user_body(identifier: str) -> dict:
        return {"externalId": identifier}
