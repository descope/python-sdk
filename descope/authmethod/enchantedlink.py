from __future__ import annotations

import requests

from descope._auth_base import AuthBase
from descope.auth import Auth
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
    LoginOptions,
    SignUpOptions,
    signup_options_to_dict,
    validate_refresh_token_provided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class EnchantedLink(AuthBase):
    def sign_in(
        self,
        login_id: str,
        uri: str,
        login_options: LoginOptions | None = None,
        refresh_token: str | None = None,
    ) -> dict:
        if not login_id:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "login_id is empty",
            )

        validate_refresh_token_provided(login_options, refresh_token)

        body = EnchantedLink._compose_signin_body(login_id, uri, login_options)
        url = EnchantedLink._compose_signin_url()
        response = self._http.post(url, body=body, pswd=refresh_token)
        return EnchantedLink._get_pending_ref_from_response(response)

    def sign_up(
        self,
        login_id: str,
        uri: str,
        user: dict | None,
        signup_options: SignUpOptions | None = None,
    ) -> dict:
        if not user:
            user = {}

        if not self._auth.adjust_and_verify_delivery_method(
            DeliveryMethod.EMAIL, login_id, user
        ):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Login ID {login_id} is not valid for email",
            )

        body = EnchantedLink._compose_signup_body(login_id, uri, user, signup_options)
        url = EnchantedLink._compose_signup_url()
        response = self._http.post(url, body=body)
        return EnchantedLink._get_pending_ref_from_response(response)

    def sign_up_or_in(
        self, login_id: str, uri: str, signup_options: SignUpOptions | None = None
    ) -> dict:
        login_options: LoginOptions | None = None
        if signup_options is not None:
            login_options = LoginOptions(
                custom_claims=signup_options.customClaims,
                template_options=signup_options.templateOptions,
                template_id=signup_options.templateId,
            )

        body = EnchantedLink._compose_signin_body(
            login_id,
            uri,
            login_options,
        )
        url = EnchantedLink._compose_sign_up_or_in_url()
        response = self._http.post(url, body=body)
        return EnchantedLink._get_pending_ref_from_response(response)

    def get_session(self, pending_ref: str) -> dict:
        uri = EndpointsV1.get_session_enchantedlink_auth_path
        body = EnchantedLink._compose_get_session_body(pending_ref)
        response = self._http.post(uri, body=body)
        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), None
        )
        return jwt_response

    def verify(self, token: str):
        uri = EndpointsV1.verify_enchantedlink_auth_path
        body = EnchantedLink._compose_verify_body(token)
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
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_email(email)

        body = EnchantedLink._compose_update_user_email_body(
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
        login_id: str,
        uri: str,
        login_options: LoginOptions | None = None,
    ) -> dict:
        return {
            "loginId": login_id,
            "URI": uri,
            "loginOptions": login_options.__dict__ if login_options else {},
        }

    @staticmethod
    def _compose_signup_body(
        login_id: str,
        uri: str,
        user: dict | None = None,
        signup_options: SignUpOptions | None = None,
    ) -> dict:
        body: dict[str, str | bool | dict] = {"loginId": login_id, "URI": uri}

        if signup_options is not None:
            body["loginOptions"] = signup_options_to_dict(signup_options)

        if user is not None:
            body["user"] = user
            method_str, val = Auth.get_login_id_by_method(DeliveryMethod.EMAIL, user)
            body[method_str] = val
        return body

    @staticmethod
    def _compose_verify_body(token: str) -> dict:
        return {"token": token}

    @staticmethod
    def _compose_update_user_email_body(
        login_id: str,
        email: str,
        add_to_login_ids: bool,
        on_merge_use_existing: bool,
        template_options: dict | None = None,
        template_id: str | None = None,
        provider_id: str | None = None,
    ) -> dict:
        body: dict[str, str | bool | dict] = {
            "loginId": login_id,
            "email": email,
            "addToLoginIDs": add_to_login_ids,
            "onMergeUseExisting": on_merge_use_existing,
        }
        if template_options is not None:
            body["templateOptions"] = template_options
        if template_id is not None:
            body["templateId"] = template_id
        if provider_id is not None:
            body["providerId"] = provider_id

        return body

    @staticmethod
    def _compose_get_session_body(pending_ref: str) -> dict:
        return {"pendingRef": pending_ref}

    @staticmethod
    def _get_pending_ref_from_response(response: requests.Response) -> dict:
        return response.json()
