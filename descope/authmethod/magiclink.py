import json
import string
import requests
from descope.authhelper import AuthHelper

from descope.common import (
    DEFAULT_BASE_URI,
    DeliveryMethod,
    EndpointsV1,
    REFRESH_SESSION_COOKIE_NAME,
)
from descope.exceptions import AuthException

class MagicLink():
    def __init__(self, auth_helper: AuthHelper):
        self._auth_helper = auth_helper

    def sign_in(
        self, method: DeliveryMethod, identifier: str, uri: str
    ) -> None:
        if not self._auth_helper._verify_delivery_method(method, identifier):
            raise AuthException(
                500,
                "identifier failure",
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = self._compose_signin_body(identifier, uri, False)
        uri = self._compose_signin_url(method)

        self._auth_helper.do_post(uri, body)

    def sign_up(
            self, method: DeliveryMethod, identifier: str, uri: str, user: dict = None
        ) -> None:
            if not self._auth_helper._verify_delivery_metho(method, identifier):
                raise AuthException(
                    500,
                    "identifier failure",
                    f"Identifier {identifier} is not valid by delivery method {method}",
                )

            body = self._compose_signup_body(method, identifier, uri, False, user)
            uri = self._compose_signup_url(method)
            self._auth_helper.do_post(uri, body)
            
    def sign_up_or_in(
        self, method: DeliveryMethod, identifier: str, uri: str
    ) -> None:
        if not self._auth_helper._verify_delivery_method(method, identifier):
            raise AuthException(
                500,
                "identifier failure",
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = self._compose_signin_body(identifier, uri, False)
        uri = self._compose_sign_up_or_in_url(method)
        self._auth_helper.do_post(uri, body)

    def verify(self, token: str) -> dict:
            uri = EndpointsV1.verifyMagicLinkAuthPath
            body = self._compose_verify_body(token)
            response = self._auth_helper.do_post(uri, body)
        

            resp = response.json()
            jwt_response = self._auth_helper._generate_jwt_response(
                resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
            )
            return jwt_response

    def _compose_signin_url(self, method: DeliveryMethod) -> str:
        return self._auth_helper._compose_url(EndpointsV1.signInAuthMagicLinkPath, method)

    def _compose_signup_url(self, method: DeliveryMethod) -> str:
        return self._auth_helper._compose_url(EndpointsV1.signUpAuthMagicLinkPath, method)
        
    def _compose_sign_up_or_in_url(self, method: DeliveryMethod) -> str:
        return self._auth_helper._compose_url(EndpointsV1.signUpOrInAuthMagicLinkPath, method)

    @staticmethod
    def _compose_signin_body(identifier: string, uri: string, cross_device: bool) -> dict:
        return {
            "externalId": identifier,
            "URI": uri,
            "crossDevice": cross_device,
        }
    
    def _compose_signup_body(self, method: DeliveryMethod, identifier: string, uri: string, cross_device: bool, user: dict) -> dict:
        body = {
            "externalId": identifier,
            "URI": uri,
            "crossDevice": cross_device,
        }

        if user is not None:
            body["user"] = user
            method_str, val = self._auth_helper._get_identifier_by_method(method, user)
            body[method_str] = val

    @staticmethod
    def _compose_verify_body(token: string) -> dict:
        return {
            "token": token,
        }
