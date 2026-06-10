from __future__ import annotations

from typing import Iterable, Optional, Union

from descope._auth_base import AuthBase
from descope.authmethod._webauthn_base import WebAuthnBase
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)


class WebAuthn(WebAuthnBase, AuthBase):
    def sign_up_start(
        self,
        login_id: Optional[str],
        origin: Optional[str],
        user: Optional[dict] = None,
    ) -> dict:
        """
        Docs
        """
        self._validate_login_id(login_id)
        self._validate_origin(origin)

        if not user:
            user = {}

        uri = EndpointsV1.sign_up_auth_webauthn_start_path
        body = self._compose_sign_up_start_body(login_id, user, origin)
        response = self._http.post(uri, body=body)
        return response.json()

    def sign_up_finish(
        self,
        transaction_id: str,
        response,
        audience: Union[str, None, Iterable[str]] = None,
    ) -> dict:
        """
        Docs
        """
        self._validate_transaction_id(transaction_id)
        self._validate_response(response)
        uri = EndpointsV1.sign_up_auth_webauthn_finish_path
        body = self._compose_sign_up_in_finish_body(transaction_id, response)
        http_response = self._http.post(uri, body=body)
        resp = http_response.json()
        return self._auth.generate_jwt_response(resp, http_response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience)

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
        self._validate_login_id(login_id)
        self._validate_origin(origin)

        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.sign_in_auth_webauthn_start_path
        body = self._compose_sign_in_start_body(login_id, origin, login_options)
        response = self._http.post(uri, body=body, pswd=refresh_token)
        return response.json()

    def sign_in_finish(
        self,
        transaction_id: str,
        response,
        audience: Union[str, None, Iterable[str]] = None,
    ) -> dict:
        """
        Docs
        """
        self._validate_transaction_id(transaction_id)
        self._validate_response(response)

        uri = EndpointsV1.sign_in_auth_webauthn_finish_path
        body = self._compose_sign_up_in_finish_body(transaction_id, response)
        http_response = self._http.post(uri, body=body)
        resp = http_response.json()
        return self._auth.generate_jwt_response(resp, http_response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience)

    def sign_up_or_in_start(
        self,
        login_id: str,
        origin: str,
    ) -> dict:
        """
        Docs
        """
        self._validate_login_id(login_id)
        self._validate_origin(origin)

        uri = EndpointsV1.sign_up_or_in_auth_webauthn_start_path
        body = self._compose_sign_up_or_in_start_body(login_id, origin)
        response = self._http.post(uri, body=body)
        return response.json()

    def update_start(self, login_id: str, refresh_token: str, origin: str) -> dict:
        """
        Docs
        """
        self._validate_login_id(login_id)
        self._validate_refresh_token(refresh_token)

        uri = EndpointsV1.update_auth_webauthn_start_path
        body = self._compose_update_start_body(login_id, origin)
        response = self._http.post(uri, body=body, pswd=refresh_token)
        return response.json()

    def update_finish(self, transaction_id: str, response: str) -> None:
        """
        Docs
        """
        self._validate_transaction_id(transaction_id)
        self._validate_response(response)

        uri = EndpointsV1.update_auth_webauthn_finish_path
        body = self._compose_update_finish_body(transaction_id, response)
        self._http.post(uri, body=body)
