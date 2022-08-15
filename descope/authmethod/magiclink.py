import string

import requests

from descope.auth import Auth
from descope.common import REFRESH_SESSION_COOKIE_NAME, DeliveryMethod, EndpointsV1
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class MagicLink:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def sign_in(self, method: DeliveryMethod, identifier: str, uri: str) -> None:
        self._sign_in(method, identifier, uri, False)

    def sign_up(
        self, method: DeliveryMethod, identifier: str, uri: str, user: dict = None
    ) -> None:
        self._sign_up(method, identifier, uri, False, user)

    def sign_up_or_in(self, method: DeliveryMethod, identifier: str, uri: str) -> dict:
        self._sign_up_or_in(method, identifier, uri, False)

    def sign_in_cross_device(
        self, method: DeliveryMethod, identifier: str, uri: str
    ) -> dict:
        response = self._sign_in(method, identifier, uri, True)
        return MagicLink._get_pending_ref_from_response(response)

    def sign_up_cross_device(
        self, method: DeliveryMethod, identifier: str, uri: str, user: dict = None
    ) -> None:
        response = self._sign_up(method, identifier, uri, True, user)
        return MagicLink._get_pending_ref_from_response(response)

    def sign_up_or_in_cross_device(
        self, method: DeliveryMethod, identifier: str, uri: str
    ) -> dict:
        response = self._sign_up_or_in(method, identifier, uri, True)
        return MagicLink._get_pending_ref_from_response(response)

    def get_session(self, pending_ref: str) -> dict:
        uri = EndpointsV1.getSessionMagicLinkAuthPath
        body = MagicLink._compose_get_session_body(pending_ref)
        response = self._auth.do_post(uri, body)

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def verify(self, token: str) -> dict:
        uri = EndpointsV1.verifyMagicLinkAuthPath
        body = MagicLink._compose_verify_body(token)
        response = self._auth.do_post(uri, body)
        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def update_user_email(
        self, identifier: str, email: str, refresh_token: str
    ) -> None:
        self._update_user_email(identifier, email, refresh_token, False)

    def update_user_email_cross_device(
        self, identifier: str, email: str, refresh_token: str
    ) -> dict:
        response = self._update_user_email(identifier, email, refresh_token, True)
        return MagicLink._get_pending_ref_from_response(response)

    def update_user_phone(
        self, method: DeliveryMethod, identifier: str, phone: str, refresh_token: str
    ) -> None:
        self._update_user_phone(method, identifier, phone, refresh_token, False)

    def update_user_phone_cross_device(
        self, method: DeliveryMethod, identifier: str, phone: str, refresh_token: str
    ) -> dict:
        response = self._update_user_phone(
            method, identifier, phone, refresh_token, True
        )
        return MagicLink._get_pending_ref_from_response(response)

    def _sign_in(
        self, method: DeliveryMethod, identifier: str, uri: str, cross_device: bool
    ) -> requests.Response:
        if not identifier:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "Identifier is empty",
            )

        body = MagicLink._compose_signin_body(identifier, uri, cross_device)
        uri = MagicLink._compose_signin_url(method)

        return self._auth.do_post(uri, body)

    def _sign_up(
        self,
        method: DeliveryMethod,
        identifier: str,
        uri: str,
        cross_device: bool,
        user: dict = None,
    ) -> requests.Response:
        if not self._auth.verify_delivery_method(method, identifier, user):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = MagicLink._compose_signup_body(
            method, identifier, uri, cross_device, user
        )
        uri = MagicLink._compose_signup_url(method)
        return self._auth.do_post(uri, body)

    def _sign_up_or_in(
        self, method: DeliveryMethod, identifier: str, uri: str, cross_device: bool
    ) -> requests.Response:

        body = MagicLink._compose_signin_body(identifier, uri, cross_device)
        uri = MagicLink._compose_sign_up_or_in_url(method)
        return self._auth.do_post(uri, body)

    def _update_user_email(
        self, identifier: str, email: str, refresh_token: str, cross_device: bool
    ) -> requests.Response:
        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_email(email)

        body = MagicLink._compose_update_user_email_body(
            identifier, email, cross_device
        )
        uri = EndpointsV1.updateUserEmailOTPPath
        return self._auth.do_post(uri, body, refresh_token)

    def _update_user_phone(
        self,
        method: DeliveryMethod,
        identifier: str,
        phone: str,
        refresh_token: str,
        cross_device: bool,
    ) -> requests.Response:
        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_phone(method, phone)

        body = MagicLink._compose_update_user_phone_body(
            identifier, phone, cross_device
        )
        uri = EndpointsV1.updateUserPhoneOTPPath
        return self._auth.do_post(uri, body, refresh_token)

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
        identifier: string, uri: string, cross_device: bool
    ) -> dict:
        return {
            "externalId": identifier,
            "URI": uri,
            "crossDevice": cross_device,
        }

    @staticmethod
    def _compose_signup_body(
        method: DeliveryMethod,
        identifier: string,
        uri: string,
        cross_device: bool,
        user: dict = None,
    ) -> dict:
        body = {
            "externalId": identifier,
            "URI": uri,
            "crossDevice": cross_device,
        }

        if user is not None:
            body["user"] = user
            method_str, val = Auth.get_identifier_by_method(method, user)
            body[method_str] = val
        return body

    @staticmethod
    def _compose_verify_body(token: string) -> dict:
        return {
            "token": token,
        }

    @staticmethod
    def _compose_update_user_email_body(
        identifier: str, email: str, cross_device: bool
    ) -> dict:
        return {"externalId": identifier, "email": email, "crossDevice": cross_device}

    @staticmethod
    def _compose_update_user_phone_body(
        identifier: str, phone: str, cross_device: bool
    ) -> dict:
        return {"externalId": identifier, "phone": phone, "crossDevice": cross_device}

    @staticmethod
    def _compose_get_session_body(pending_ref: str) -> dict:
        return {"pendingRef": pending_ref}

    @staticmethod
    def _get_pending_ref_from_response(response: requests.Response) -> dict:
        return response.json()
