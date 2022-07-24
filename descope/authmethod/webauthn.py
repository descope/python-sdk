from descope.authhelper import AuthHelper
from descope.common import REFRESH_SESSION_COOKIE_NAME, EndpointsV1
from descope.exceptions import AuthException


class WebauthN:
    _auth_helper: AuthHelper

    def __init__(self, auth_helper):
        self._auth_helper = auth_helper

    def sign_up_start(self, identifier: str, user: dict = None) -> dict:
        """
        Docs
        """
        if not identifier:
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        uri = EndpointsV1.signUpAuthWebauthnStart
        body = WebauthN._compose_signup_body(identifier, user)
        response = self._auth_helper.do_post(uri, body)

        return response.json()

    def sign_up_finish(self, transactionID: str, response: str) -> dict:
        """
        Docs
        """
        if not transactionID:
            raise AuthException(
                500, "Invalid argument", "TransactionID cannot be empty"
            )

        if not response:
            raise AuthException(500, "Invalid argument", "Response cannot be empty")

        uri = EndpointsV1.signUpAuthWebauthnFinish
        body = WebauthN._compose_sign_up_in_finish_body(transactionID, response)
        response = self._auth_helper.do_post(uri, body)

        resp = response.json()
        jwt_response = self._auth_helper._generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def sign_in_start(self, identifier: str) -> dict:
        """
        Docs
        """
        if not identifier:
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        uri = EndpointsV1.signInAuthWebauthnStart
        body = WebauthN._compose_signin_body(identifier)
        response = self._auth_helper.do_post(uri, body)

        return response.json()

    def sign_in_finish(self, transactionID: str, response: str) -> dict:
        """
        Docs
        """
        if not transactionID:
            raise AuthException(
                500, "Invalid argument", "TransactionID cannot be empty"
            )

        if not response:
            raise AuthException(500, "Invalid argument", "Response cannot be empty")

        uri = EndpointsV1.signInAuthWebauthnFinish
        body = WebauthN._compose_sign_up_in_finish_body(transactionID, response)
        response = self._auth_helper.do_post(uri, body)

        resp = response.json()
        jwt_response = self._auth_helper._generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def add_device_start(self, identifier: str, refresh_token: str):
        """
        Docs
        """
        if not identifier:
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        if not refresh_token:
            raise AuthException(
                500, "Invalid argument", "Refresh token cannot be empty"
            )

        uri = EndpointsV1.deviceAddAuthWebauthnStart
        body = WebauthN._compose_add_device_start_body(identifier)
        response = self._auth_helper.do_post(uri, body, None, refresh_token)

        return response.json()

    def add_device_finish(self, transactionID: str, response: str) -> dict:
        """
        Docs
        """
        if not transactionID:
            raise AuthException(
                500, "Invalid argument", "TransactionID cannot be empty"
            )

        if not response:
            raise AuthException(500, "Invalid argument", "Response cannot be empty")

        uri = EndpointsV1.deviceAddAuthWebauthnFinish
        body = WebauthN._compose_sign_up_in_finish_body(transactionID, response)
        response = self._auth_helper.do_post(uri, body)

    @staticmethod
    def _compose_signup_body(identifier: str, user: dict) -> dict:
        body = {"user": {"externalId": identifier}}
        if user is not None:
            for key, val in user.items():
                body["user"][key] = val
        return body

    @staticmethod
    def _compose_signin_body(identifier: str) -> dict:
        return {"externalId": identifier}

    @staticmethod
    def _compose_sign_up_in_finish_body(transactionID: str, response: str) -> dict:
        return {"transactionID": transactionID, "response": response}

    @staticmethod
    def _compose_add_device_start_body(identifier: str) -> dict:
        return {"externalId": identifier}

    @staticmethod
    def _compose_add_device_finish_body(transactionID: str, response: str) -> dict:
        return {"transactionID": transactionID, "response": response}