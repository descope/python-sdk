import string

import requests

from descope.auth import Auth
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
    LoginOptions,
    validateRefreshTokenProvided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class EnchantedLink:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def sign_in(
        self,
        identifier: str,
        uri: str,
        loginOptions: LoginOptions = None,
        refreshToken: str = None,
    ) -> dict:
        if not identifier:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "Identifier is empty",
            )

        validateRefreshTokenProvided(loginOptions, refreshToken)

        body = EnchantedLink._compose_signin_body(identifier, uri, loginOptions)
        uri = EnchantedLink._compose_signin_url()

        response = self._auth.do_post(uri, body, None, refreshToken)
        return EnchantedLink._get_pending_ref_from_response(response)

    def sign_up(self, identifier: str, uri: str, user: dict = None) -> None:
        if not self._auth.verify_delivery_method(
            DeliveryMethod.EMAIL, identifier, user
        ):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Identifier {identifier} is not valid for email",
            )

        body = EnchantedLink._compose_signup_body(identifier, uri, user)
        uri = EnchantedLink._compose_signup_url()
        response = self._auth.do_post(uri, body, None)
        return EnchantedLink._get_pending_ref_from_response(response)

    def sign_up_or_in(self, identifier: str, uri: str) -> dict:
        body = EnchantedLink._compose_signin_body(identifier, uri)
        uri = EnchantedLink._compose_sign_up_or_in_url()
        response = self._auth.do_post(uri, body, None)
        return EnchantedLink._get_pending_ref_from_response(response)

    def get_session(self, pending_ref: str) -> dict:
        uri = EndpointsV1.getSessionEnchantedLinkAuthPath
        body = EnchantedLink._compose_get_session_body(pending_ref)
        response = self._auth.do_post(uri, body, None)

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def verify(self, token: str):
        uri = EndpointsV1.verifyEnchantedLinkAuthPath
        body = EnchantedLink._compose_verify_body(token)
        self._auth.do_post(uri, body, None)

    def update_user_email(
        self, identifier: str, email: str, refresh_token: str
    ) -> dict:
        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_email(email)

        body = EnchantedLink._compose_update_user_email_body(identifier, email)
        uri = EndpointsV1.updateUserEmailOTPPath
        response = self._auth.do_post(uri, body, None, refresh_token)
        return EnchantedLink._get_pending_ref_from_response(response)

    @staticmethod
    def _compose_signin_url() -> str:
        return Auth.compose_url(
            EndpointsV1.signInAuthEnchantedLinkPath, DeliveryMethod.EMAIL
        )

    @staticmethod
    def _compose_signup_url() -> str:
        return Auth.compose_url(
            EndpointsV1.signUpAuthEnchantedLinkPath, DeliveryMethod.EMAIL
        )

    @staticmethod
    def _compose_sign_up_or_in_url() -> str:
        return Auth.compose_url(
            EndpointsV1.signUpOrInAuthEnchantedLinkPath, DeliveryMethod.EMAIL
        )

    @staticmethod
    def _compose_signin_body(
        identifier: string,
        uri: string,
        loginOptions: LoginOptions = None,
    ) -> dict:
        return {
            "externalId": identifier,
            "URI": uri,
            "loginOptions": loginOptions.__dict__ if loginOptions else {},
        }

    @staticmethod
    def _compose_signup_body(
        identifier: string,
        uri: string,
        user: dict = None,
    ) -> dict:
        body = {"externalId": identifier, "URI": uri}

        if user is not None:
            body["user"] = user
            method_str, val = Auth.get_identifier_by_method(DeliveryMethod.EMAIL, user)
            body[method_str] = val
        return body

    @staticmethod
    def _compose_verify_body(token: string) -> dict:
        return {"token": token}

    @staticmethod
    def _compose_update_user_email_body(identifier: str, email: str) -> dict:
        return {"externalId": identifier, "email": email}

    @staticmethod
    def _compose_get_session_body(pending_ref: str) -> dict:
        return {"pendingRef": pending_ref}

    @staticmethod
    def _get_pending_ref_from_response(response: requests.Response) -> dict:
        return response.json()
