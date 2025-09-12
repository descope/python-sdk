from typing import Iterable, Optional, Union

from requests import Response

from descope._auth_base import AuthBase
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class WebAuthn(AuthBase):
    def sign_up_start(
        self,
        login_id: Optional[str],
        origin: Optional[str],
        user: Optional[dict] = None,
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

        if not user:
            user = {}

        uri = EndpointsV1.sign_up_auth_webauthn_start_path
        body = WebAuthn._compose_sign_up_start_body(login_id, user, origin)
        response = self._http.post(uri, body=body)
        return response.json()

    def sign_up_finish(
        self,
        transaction_id: str,
        response: Response,
        audience: Union[str, None, Iterable[str]] = None,
    ) -> dict:
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
        uri = EndpointsV1.sign_up_auth_webauthn_finish_path
        body = WebAuthn._compose_sign_up_in_finish_body(transaction_id, response)
        response = self._http.post(uri, body=body)
        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience
        )
        return jwt_response

    def sign_in_start(
        self,
        login_id: str,
        origin: str,
        login_options: Optional[LoginOptions] = None,
        refresh_token: Optional[str] = None,
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

        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.sign_in_auth_webauthn_start_path
        body = WebAuthn._compose_sign_in_start_body(login_id, origin, login_options)
        response = self._http.post(uri, body=body, pswd=refresh_token)
        return response.json()

    def sign_in_finish(
        self,
        transaction_id: str,
        response: Response,
        audience: Union[str, None, Iterable[str]] = None,
    ) -> dict:
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

        uri = EndpointsV1.sign_in_auth_webauthn_finish_path
        body = WebAuthn._compose_sign_up_in_finish_body(transaction_id, response)
        response = self._http.post(uri, body=body)
        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience
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

        uri = EndpointsV1.sign_up_or_in_auth_webauthn_start_path
        body = WebAuthn._compose_sign_up_or_in_start_body(login_id, origin)
        response = self._http.post(uri, body=body)
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

        uri = EndpointsV1.update_auth_webauthn_start_path
        body = WebAuthn._compose_update_start_body(login_id, origin)
        response = self._http.post(uri, body=body, pswd=refresh_token)
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

        uri = EndpointsV1.update_auth_webauthn_finish_path
        body = WebAuthn._compose_update_finish_body(transaction_id, response)
        self._http.post(uri, body=body)

    @staticmethod
    def _compose_sign_up_start_body(login_id: str, user: dict, origin: str) -> dict:
        user.update({"loginId": login_id})
        body = {"user": user, "origin": origin}
        return body

    @staticmethod
    def _compose_sign_in_start_body(
        login_id: str, origin: str, login_options: Optional[LoginOptions] = None
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
    def _compose_sign_up_in_finish_body(
        transaction_id: str, response: Response
    ) -> dict:
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
