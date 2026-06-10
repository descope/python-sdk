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
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class MagicLinkBase:
    """Shared, I/O-free base for MagicLink auth-method classes.

    Holds only static validation guards, URL composers and body builders — no
    network I/O, no ``__init__``.  The two concrete subclasses add the network layer:

    - ``MagicLink(MagicLinkBase, AuthBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``MagicLinkAsync(MagicLinkBase, AsyncAuthBase)`` — async, uses ``self._http`` (``HTTPClientAsync``)
    """

    @staticmethod
    def _validate_sign_in_login_id(login_id: str) -> None:
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier is empty")

    @staticmethod
    def _validate_login_id(login_id: str) -> None:
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty")

    @staticmethod
    def _compose_signin_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.sign_in_auth_magiclink_path, method)

    @staticmethod
    def _compose_signup_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.sign_up_auth_magiclink_path, method)

    @staticmethod
    def _compose_sign_up_or_in_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.sign_up_or_in_auth_magiclink_path, method)

    @staticmethod
    def _compose_update_phone_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.update_user_phone_magiclink_path, method)

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
        method: DeliveryMethod,
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
            method_str, val = Auth.get_login_id_by_method(method, user)
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
