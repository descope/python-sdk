from __future__ import annotations

from typing import Iterable

from descope._auth_base import AsyncAuthBase
from descope.auth import Auth
from descope.authmethod._otp_base import OTPBase
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
    LoginOptions,
    SignUpOptions,
    validate_refresh_token_provided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class OTPAsync(OTPBase, AsyncAuthBase):
    """Async OTP auth-method. All network calls are coroutines; validation is sync (no I/O)."""

    async def sign_in(
        self,
        method: DeliveryMethod,
        login_id: str,
        login_options: LoginOptions | None = None,
        refresh_token: str | None = None,
    ) -> str:
        self._validate_login_id(login_id)

        validate_refresh_token_provided(login_options, refresh_token)

        uri = self._compose_signin_url(method)
        body = self._compose_signin_body(login_id, login_options)
        response = await self._http.post(uri, body=body, pswd=refresh_token)
        return Auth.extract_masked_address(response.json(), method)

    async def sign_up(
        self,
        method: DeliveryMethod,
        login_id: str,
        user: dict | None = None,
        signup_options: SignUpOptions | None = None,
    ) -> str:
        if not user:
            user = {}

        if not self._auth.adjust_and_verify_delivery_method(method, login_id, user):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Login ID {login_id} is not valid by delivery method {method}",
            )

        uri = self._compose_signup_url(method)
        body = self._compose_signup_body(method, login_id, user, signup_options)
        response = await self._http.post(uri, body=body)
        return Auth.extract_masked_address(response.json(), method)

    async def sign_up_or_in(
        self,
        method: DeliveryMethod,
        login_id: str,
        signup_options: SignUpOptions | None = None,
    ) -> str:
        self._validate_login_id(login_id)

        uri = self._compose_sign_up_or_in_url(method)
        login_options: LoginOptions | None = None
        if signup_options is not None:
            login_options = LoginOptions(
                custom_claims=signup_options.customClaims,
                template_options=signup_options.templateOptions,
                template_id=signup_options.templateId,
            )
        body = self._compose_signin_body(login_id, login_options)
        response = await self._http.post(uri, body=body)
        return Auth.extract_masked_address(response.json(), method)

    async def verify_code(
        self,
        method: DeliveryMethod,
        login_id: str,
        code: str,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        self._validate_login_id(login_id)

        uri = self._compose_verify_code_url(method)
        body = self._compose_verify_code_body(login_id, code)
        response = await self._http.post(uri, body=body)

        resp = response.json()
        return self._auth.generate_jwt_response(resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience)

    async def update_user_email(
        self,
        login_id: str,
        email: str,
        refresh_token: str,
        add_to_login_ids: bool = False,
        on_merge_use_existing: bool = False,
        template_options: dict | None = None,
        template_id: str | None = None,
        provider_id: str | None = None,
    ) -> str:
        self._validate_login_id(login_id)

        Auth.validate_email(email)

        uri = EndpointsV1.update_user_email_otp_path
        body = self._compose_update_user_email_body(
            login_id,
            email,
            add_to_login_ids,
            on_merge_use_existing,
            template_options,
            template_id,
            provider_id,
        )
        response = await self._http.post(uri, body=body, pswd=refresh_token)
        return Auth.extract_masked_address(response.json(), DeliveryMethod.EMAIL)

    async def update_user_phone(
        self,
        method: DeliveryMethod,
        login_id: str,
        phone: str,
        refresh_token: str,
        add_to_login_ids: bool = False,
        on_merge_use_existing: bool = False,
        template_options: dict | None = None,
        template_id: str | None = None,
        provider_id: str | None = None,
    ) -> str:
        self._validate_login_id(login_id)

        Auth.validate_phone(method, phone)

        uri = self._compose_update_phone_url(method)
        body = self._compose_update_user_phone_body(
            login_id,
            phone,
            add_to_login_ids,
            on_merge_use_existing,
            template_options,
            template_id,
            provider_id,
        )
        response = await self._http.post(uri, body=body, pswd=refresh_token)
        return Auth.extract_masked_address(response.json(), method)
