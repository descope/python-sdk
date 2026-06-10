from __future__ import annotations

from descope._auth_base import AuthBase
from descope.auth import Auth
from descope.authmethod._enchantedlink_base import EnchantedLinkBase
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
    LoginOptions,
    SignUpOptions,
    validate_refresh_token_provided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class EnchantedLink(EnchantedLinkBase, AuthBase):
    def sign_in(
        self,
        login_id: str,
        uri: str,
        login_options: LoginOptions | None = None,
        refresh_token: str | None = None,
    ) -> dict:
        self._validate_sign_in_login_id(login_id)

        validate_refresh_token_provided(login_options, refresh_token)

        body = self._compose_signin_body(login_id, uri, login_options)
        url = self._compose_signin_url()
        response = self._http.post(url, body=body, pswd=refresh_token)
        return response.json()

    def sign_up(
        self,
        login_id: str,
        uri: str,
        user: dict | None,
        signup_options: SignUpOptions | None = None,
    ) -> dict:
        if not user:
            user = {}

        if not self._auth.adjust_and_verify_delivery_method(DeliveryMethod.EMAIL, login_id, user):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Login ID {login_id} is not valid for email",
            )

        body = self._compose_signup_body(login_id, uri, user, signup_options)
        url = self._compose_signup_url()
        response = self._http.post(url, body=body)
        return response.json()

    def sign_up_or_in(self, login_id: str, uri: str, signup_options: SignUpOptions | None = None) -> dict:
        login_options: LoginOptions | None = None
        if signup_options is not None:
            login_options = LoginOptions(
                custom_claims=signup_options.customClaims,
                template_options=signup_options.templateOptions,
                template_id=signup_options.templateId,
            )

        body = self._compose_signin_body(login_id, uri, login_options)
        url = self._compose_sign_up_or_in_url()
        response = self._http.post(url, body=body)
        return response.json()

    def get_session(self, pending_ref: str) -> dict:
        uri = EndpointsV1.get_session_enchantedlink_auth_path
        body = self._compose_get_session_body(pending_ref)
        response = self._http.post(uri, body=body)
        resp = response.json()
        return self._auth.generate_jwt_response(resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), None)

    def verify(self, token: str) -> None:
        uri = EndpointsV1.verify_enchantedlink_auth_path
        body = self._compose_verify_body(token)
        self._http.post(uri, body=body)

    def update_user_email(
        self,
        login_id: str,
        email: str,
        refresh_token: str,
        add_to_login_ids: bool = False,
        on_merge_use_existing: bool = False,
        template_options: dict | None = None,
        template_id: str | None = None,
        provider_id: str | None = None,
    ) -> dict:
        self._validate_login_id(login_id)

        Auth.validate_email(email)

        body = self._compose_update_user_email_body(
            login_id,
            email,
            add_to_login_ids,
            on_merge_use_existing,
            template_options,
            template_id,
            provider_id,
        )
        uri = EndpointsV1.update_user_email_enchantedlink_path
        response = self._http.post(uri, body=body, pswd=refresh_token)
        return response.json()
