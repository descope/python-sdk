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


class EnchantedLinkBase:
    """Shared, I/O-free base for EnchantedLink auth-method classes.

    Holds only static URL composers and body builders — no network I/O, no
    ``__init__``.  The two concrete subclasses add the network layer:

    - ``EnchantedLink(EnchantedLinkBase, AuthBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``EnchantedLinkAsync(EnchantedLinkBase, AsyncAuthBase)`` — async, uses ``self._http``
    """

    @staticmethod
    def _compose_signin_url() -> str:
        return Auth.compose_url(EndpointsV1.sign_in_auth_enchantedlink_path, DeliveryMethod.EMAIL)

    @staticmethod
    def _compose_signup_url() -> str:
        return Auth.compose_url(EndpointsV1.sign_up_auth_enchantedlink_path, DeliveryMethod.EMAIL)

    @staticmethod
    def _compose_sign_up_or_in_url() -> str:
        return Auth.compose_url(EndpointsV1.sign_up_or_in_auth_enchantedlink_path, DeliveryMethod.EMAIL)

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
