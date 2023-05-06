import string

from descope._auth_base import AuthBase
from descope.auth import Auth
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class MagicLink(AuthBase):
    def sign_in(
        self,
        method: DeliveryMethod,
        login_id: str,
        uri: str,
        login_options: LoginOptions = None,
        refresh_token: str = None,
    ) -> str:
        if not login_id:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "Identifier is empty",
            )

        validate_refresh_token_provided(login_options, refresh_token)

        body = MagicLink._compose_signin_body(login_id, uri, login_options)
        uri = MagicLink._compose_signin_url(method)

        response = self._auth.do_post(uri, body, None, refresh_token)
        return Auth.extract_masked_address(response.json(), method)

    def sign_up(
        self, method: DeliveryMethod, login_id: str, uri: str, user: dict = None
    ) -> str:
        if not user:
            user = {}

        if not self._auth.verify_delivery_method(method, login_id, user):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Login ID {login_id} is not valid by delivery method {method}",
            )

        body = MagicLink._compose_signup_body(method, login_id, uri, user)
        uri = MagicLink._compose_signup_url(method)
        response = self._auth.do_post(uri, body, None)
        return Auth.extract_masked_address(response.json(), method)

    def sign_up_or_in(self, method: DeliveryMethod, login_id: str, uri: str) -> str:
        body = MagicLink._compose_signin_body(login_id, uri)
        uri = MagicLink._compose_sign_up_or_in_url(method)
        response = self._auth.do_post(uri, body, None)
        return Auth.extract_masked_address(response.json(), method)

    def verify(self, token: str) -> dict:
        uri = EndpointsV1.verify_magiclink_auth_path
        body = MagicLink._compose_verify_body(token)
        response = self._auth.do_post(uri, body, None)
        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def update_user_email(
        self,
        login_id: str,
        email: str,
        refresh_token: str,
        add_to_login_ids: bool = False,
        on_merge_use_existing: bool = False,
    ) -> str:
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_email(email)

        body = MagicLink._compose_update_user_email_body(
            login_id, email, add_to_login_ids, on_merge_use_existing
        )
        uri = EndpointsV1.update_user_email_magiclink_path
        response = self._auth.do_post(uri, body, None, refresh_token)
        return Auth.extract_masked_address(response.json(), DeliveryMethod.EMAIL)

    def update_user_phone(
        self,
        method: DeliveryMethod,
        login_id: str,
        phone: str,
        refresh_token: str,
        add_to_login_ids: bool = False,
        on_merge_use_existing: bool = False,
    ) -> str:
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_phone(method, phone)

        body = MagicLink._compose_update_user_phone_body(
            login_id, phone, add_to_login_ids, on_merge_use_existing
        )
        uri = EndpointsV1.update_user_phone_magiclink_path
        response = self._auth.do_post(uri, body, None, refresh_token)
        return Auth.extract_masked_address(response.json(), DeliveryMethod.SMS)

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
        method: DeliveryMethod,
        login_id: string,
        uri: string,
        user: dict = None,
    ) -> dict:
        body = {"loginId": login_id, "URI": uri}

        if user is not None:
            body["user"] = user
            method_str, val = Auth.get_login_id_by_method(method, user)
            body[method_str] = val
        return body

    @staticmethod
    def _compose_verify_body(token: string) -> dict:
        return {"token": token}

    @staticmethod
    def _compose_update_user_email_body(
        login_id: str, email: str, add_to_login_ids: bool, on_merge_use_existing: bool
    ) -> dict:
        return {
            "loginId": login_id,
            "email": email,
            "addToLoginIDs": add_to_login_ids,
            "onMergeUseExisting": on_merge_use_existing,
        }

    @staticmethod
    def _compose_update_user_phone_body(
        login_id: str, phone: str, add_to_login_ids: bool, on_merge_use_existing: bool
    ) -> dict:
        return {
            "loginId": login_id,
            "phone": phone,
            "addToLoginIDs": add_to_login_ids,
            "onMergeUseExisting": on_merge_use_existing,
        }
