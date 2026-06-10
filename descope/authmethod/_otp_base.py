# This is not part of the public API but a code helper
from __future__ import annotations

from descope.auth import Auth
from descope.common import (
    DeliveryMethod,
    EndpointsV1,
    LoginOptions,
    SignUpOptions,
    signup_options_to_dict,
)


class OTPBase:
    """Shared, I/O-free base for OTP auth-method classes.

    Holds only static URL composers and body builders — no network I/O, no
    ``__init__``.  The two concrete subclasses add the network layer:

    - ``OTP(OTPBase, AuthBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``OTPAsync(OTPBase, AsyncAuthBase)`` — async, uses ``self._http`` (``HTTPClientAsync``)
    """

    @staticmethod
    def _compose_signup_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.sign_up_auth_otp_path, method)

    @staticmethod
    def _compose_signin_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.sign_in_auth_otp_path, method)

    @staticmethod
    def _compose_sign_up_or_in_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.sign_up_or_in_auth_otp_path, method)

    @staticmethod
    def _compose_verify_code_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.verify_code_auth_path, method)

    @staticmethod
    def _compose_update_phone_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.update_user_phone_otp_path, method)

    @staticmethod
    def _compose_signup_body(
        method: DeliveryMethod,
        login_id: str,
        user: dict,
        signup_options: SignUpOptions | None = None,
    ) -> dict:
        body: dict[str, str | bool | dict] = {"loginId": login_id}

        if signup_options is not None:
            body["loginOptions"] = signup_options_to_dict(signup_options)

        if user is not None:
            body["user"] = user
            method_str, val = Auth.get_login_id_by_method(method, user)
            body[method_str] = val
        return body

    @staticmethod
    def _compose_signin_body(login_id: str, login_options: LoginOptions | None = None) -> dict:
        return {
            "loginId": login_id,
            "loginOptions": login_options.__dict__ if login_options else {},
        }

    @staticmethod
    def _compose_verify_code_body(login_id: str, code: str) -> dict:
        return {"loginId": login_id, "code": code}

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
    def _compose_update_user_phone_body(
        login_id: str,
        phone: str,
        add_to_login_ids: bool,
        on_merge_use_existing: bool,
        template_options: dict | None = None,
        template_id: str | None = None,
        provider_id: str | None = None,
    ) -> dict:
        body: dict[str, str | bool | dict] = {
            "loginId": login_id,
            "phone": phone,
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
