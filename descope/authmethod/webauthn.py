from descope.auth import Auth
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
    validateRefreshTokenProvided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class WebAuthn:
    _auth: Auth

    def __init__(self, auth):
        self._auth = auth

    def sign_up_start(self, login_id: str, origin: str, user: dict = None) -> dict:
        """
        Docs
        """
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        if not origin:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Origin cannot be empty"
            )

        if not user:
            user = {}

        uri = EndpointsV1.signUpAuthWebauthnStart
        body = WebAuthn._compose_sign_up_start_body(login_id, user, origin)
        response = self._auth.do_post(uri, body)

        return response.json()

    def sign_up_finish(self, transactionID: str, response: str) -> dict:
        """
        Docs
        """
        if not transactionID:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Transaction id cannot be empty"
            )

        if not response:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Response cannot be empty"
            )

        uri = EndpointsV1.signUpAuthWebauthnFinish
        body = WebAuthn._compose_sign_up_in_finish_body(transactionID, response)
        response = self._auth.do_post(uri, body, None, "")

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def sign_in_start(
        self,
        login_id: str,
        origin: str,
        login_options: LoginOptions = None,
        refresh_token: str = None,
    ) -> dict:
        """
        Docs
        """
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        if not origin:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Origin cannot be empty"
            )

        validateRefreshTokenProvided(login_options, refresh_token)

        uri = EndpointsV1.signInAuthWebauthnStart
        body = WebAuthn._compose_sign_in_start_body(login_id, origin, login_options)
        response = self._auth.do_post(uri, body, pswd=refresh_token)

        return response.json()

    def sign_in_finish(self, transaction_id: str, response: str) -> dict:
        """
        Docs
        """
        if not transaction_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Transaction id cannot be empty"
            )

        if not response:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Response cannot be empty"
            )

        uri = EndpointsV1.signInAuthWebauthnFinish
        body = WebAuthn._compose_sign_up_in_finish_body(transaction_id, response)
        response = self._auth.do_post(uri, body, None)

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def sign_up_or_in_start(
        self,
        login_id: str,
        origin: str,
    ) -> dict:
        """
        Docs
        """
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        if not origin:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Origin cannot be empty"
            )

        uri = EndpointsV1.signUpOrInAuthWebauthnStart
        body = WebAuthn._compose_sign_up_or_in_start_body(login_id, origin)
        response = self._auth.do_post(uri, body)

        return response.json()

    def update_start(self, login_id: str, refresh_token: str, origin: str):
        """
        Docs
        """
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        if not refresh_token:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Refresh token cannot be empty"
            )

        uri = EndpointsV1.updateAuthWebauthnStart
        body = WebAuthn._compose_update_start_body(login_id, origin)
        response = self._auth.do_post(uri, body, None, refresh_token)

        return response.json()

    def update_finish(self, transaction_id: str, response: str) -> None:
        """
        Docs
        """
        if not transaction_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Transaction id cannot be empty"
            )

        if not response:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Response cannot be empty"
            )

        uri = EndpointsV1.updateAuthWebauthnFinish
        body = WebAuthn._compose_update_finish_body(transaction_id, response)
        self._auth.do_post(uri, body)

    @staticmethod
    def _compose_sign_up_start_body(login_id: str, user: dict, origin: str) -> dict:
        body = {"user": {"loginId": login_id}}
        if user is not None:
            for key, val in user.items():
                body["user"][key] = val
        body["origin"] = origin
        return body

    @staticmethod
    def _compose_sign_in_start_body(
        login_id: str, origin: str, login_options: LoginOptions = None
    ) -> dict:
        return {
            "loginId": login_id,
            "origin": origin,
            "loginOptions": login_options.__dict__ if login_options else {},
        }

    @staticmethod
    def _compose_sign_up_or_in_start_body(login_id: str, origin: str) -> dict:
        return {
            "loginId": login_id,
            "origin": origin,
        }

    @staticmethod
    def _compose_sign_up_in_finish_body(transaction_id: str, response: str) -> dict:
        return {"transactionId": transaction_id, "response": response}

    @staticmethod
    def _compose_update_start_body(login_id: str, origin: str) -> dict:
        body = {"loginId": login_id}
        if origin:
            body["origin"] = origin
        return body

    @staticmethod
    def _compose_update_finish_body(transaction_id: str, response: str) -> dict:
        return {"transactionId": transaction_id, "response": response}
