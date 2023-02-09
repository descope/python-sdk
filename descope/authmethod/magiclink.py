import string

from descope.auth import Auth
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
    LoginOptions,
    validateRefreshTokenProvided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class MagicLink:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def sign_in(
        self,
        method: DeliveryMethod,
        login_id: str,
        uri: str,
        login_options: LoginOptions = None,
        refresh_token: str = None,
    ) -> None:
        if not login_id:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "Identifier is empty",
            )

        validateRefreshTokenProvided(login_options, refresh_token)

        body = MagicLink._compose_signin_body(login_id, uri, login_options)
        uri = MagicLink._compose_signin_url(method)

        self._auth.do_post(uri, body, None, refresh_token)

    def sign_up(
        self, method: DeliveryMethod, login_id: str, uri: str, user: dict = None
    ) -> None:

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
        self._auth.do_post(uri, body, None)

    def sign_up_or_in(self, method: DeliveryMethod, login_id: str, uri: str) -> None:
        body = MagicLink._compose_signin_body(login_id, uri)
        uri = MagicLink._compose_sign_up_or_in_url(method)
        self._auth.do_post(uri, body, None)

    def verify(self, token: str) -> dict:
        uri = EndpointsV1.verifyMagicLinkAuthPath
        body = MagicLink._compose_verify_body(token)
        response = self._auth.do_post(uri, body, None)
        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def update_user_email(self, login_id: str, email: str, refresh_token: str) -> None:
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_email(email)

        body = MagicLink._compose_update_user_email_body(login_id, email)
        uri = EndpointsV1.updateUserEmailOTPPath
        self._auth.do_post(uri, body, None, refresh_token)

    def update_user_phone(
        self, method: DeliveryMethod, login_id: str, phone: str, refresh_token: str
    ) -> None:
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_phone(method, phone)

        body = MagicLink._compose_update_user_phone_body(login_id, phone)
        uri = EndpointsV1.updateUserPhoneOTPPath
        self._auth.do_post(uri, body, None, refresh_token)

    @staticmethod
    def _compose_signin_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.signInAuthMagicLinkPath, method)

    @staticmethod
    def _compose_signup_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.signUpAuthMagicLinkPath, method)

    @staticmethod
    def _compose_sign_up_or_in_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.signUpOrInAuthMagicLinkPath, method)

    @staticmethod
    def _compose_update_phone_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.updateUserPhoneMagicLinkPath, method)

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
    def _compose_update_user_email_body(login_id: str, email: str) -> dict:
        return {"loginId": login_id, "email": email}

    @staticmethod
    def _compose_update_user_phone_body(login_id: str, phone: str) -> dict:
        return {"loginId": login_id, "phone": phone}
