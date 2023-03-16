import string

import requests

from descope.auth import Auth
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class EnchantedLink:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def sign_in(
        self,
        login_id: str,
        uri: str,
        login_options: LoginOptions = None,
        refresh_token: str = None,
    ) -> dict:
        if not login_id:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "login_id is empty",
            )

        validate_refresh_token_provided(login_options, refresh_token)

        body = EnchantedLink._compose_signin_body(login_id, uri, login_options)
        uri = EnchantedLink._compose_signin_url()

        response = self._auth.do_post(uri, body, None, refresh_token)
        return EnchantedLink._get_pending_ref_from_response(response)

    def sign_up(self, login_id: str, uri: str, user: dict = None) -> dict:
        if not user:
            user = {}

        if not self._auth.verify_delivery_method(DeliveryMethod.EMAIL, login_id, user):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Login ID {login_id} is not valid for email",
            )

        body = EnchantedLink._compose_signup_body(login_id, uri, user)
        uri = EnchantedLink._compose_signup_url()
        response = self._auth.do_post(uri, body, None)
        return EnchantedLink._get_pending_ref_from_response(response)

    def sign_up_or_in(self, login_id: str, uri: str) -> dict:
        body = EnchantedLink._compose_signin_body(login_id, uri)
        uri = EnchantedLink._compose_sign_up_or_in_url()
        response = self._auth.do_post(uri, body, None)
        return EnchantedLink._get_pending_ref_from_response(response)

    def get_session(self, pending_ref: str) -> dict:
        uri = EndpointsV1.get_session_enchantedlink_auth_path
        body = EnchantedLink._compose_get_session_body(pending_ref)
        response = self._auth.do_post(uri, body, None)

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def verify(self, token: str):
        uri = EndpointsV1.verify_enchantedlink_auth_path
        body = EnchantedLink._compose_verify_body(token)
        self._auth.do_post(uri, body, None)

    def update_user_email(self, login_id: str, email: str, refresh_token: str) -> dict:
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_email(email)

        body = EnchantedLink._compose_update_user_email_body(login_id, email)
        uri = EndpointsV1.update_user_email_otp_path
        response = self._auth.do_post(uri, body, None, refresh_token)
        return EnchantedLink._get_pending_ref_from_response(response)

    @staticmethod
    def _compose_signin_url() -> str:
        return Auth.compose_url(
            EndpointsV1.sign_in_auth_enchantedlink_path, DeliveryMethod.EMAIL
        )

    @staticmethod
    def _compose_signup_url() -> str:
        return Auth.compose_url(
            EndpointsV1.sign_up_auth_enchantedlink_path, DeliveryMethod.EMAIL
        )

    @staticmethod
    def _compose_sign_up_or_in_url() -> str:
        return Auth.compose_url(
            EndpointsV1.sign_up_or_in_auth_enchantedlink_path, DeliveryMethod.EMAIL
        )

    @staticmethod
    def _compose_signin_body(
        login_id: string,
        uri: string,
        login_options: LoginOptions = None,
    ) -> dict:
        return {
            "loginId": login_id,
            "URI": uri,
            "loginOptions": login_options.__dict__ if login_options else {},
        }

    @staticmethod
    def _compose_signup_body(
        login_id: string,
        uri: string,
        user: dict = None,
    ) -> dict:
        body = {"loginId": login_id, "URI": uri}

        if user is not None:
            body["user"] = user
            method_str, val = Auth.get_login_id_by_method(DeliveryMethod.EMAIL, user)
            body[method_str] = val
        return body

    @staticmethod
    def _compose_verify_body(token: string) -> dict:
        return {"token": token}

    @staticmethod
    def _compose_update_user_email_body(login_id: str, email: str) -> dict:
        return {"loginId": login_id, "email": email}

    @staticmethod
    def _compose_get_session_body(pending_ref: str) -> dict:
        return {"pendingRef": pending_ref}

    @staticmethod
    def _get_pending_ref_from_response(response: requests.Response) -> dict:
        return response.json()
