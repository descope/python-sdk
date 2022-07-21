import string
from descope.authhelper import AuthHelper

from descope.common import (
    DEFAULT_BASE_URI,
    DeliveryMethod,
    EndpointsV1,
    REFRESH_SESSION_COOKIE_NAME,
)
from descope.exceptions import AuthException

class MagicLink():
    _auth_helper: AuthHelper

    def __init__(self, auth_helper: AuthHelper):
        self._auth_helper = auth_helper

    def sign_in(
        self, method: DeliveryMethod, identifier: str, uri: str
    ) -> None:
        if not self._auth_helper.verify_delivery_method(method, identifier):
            raise AuthException(
                500,
                "identifier failure",
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = MagicLink._compose_signin_body(identifier, uri, False)
        uri = MagicLink._compose_signin_url(method)

        self._auth_helper.do_post(uri, body)

    def sign_up(
            self, method: DeliveryMethod, identifier: str, uri: str, user: dict = None
        ) -> None:
            if not self._auth_helper.verify_delivery_method(method, identifier):
                raise AuthException(
                    500,
                    "identifier failure",
                    f"Identifier {identifier} is not valid by delivery method {method}",
                )

            body = MagicLink._compose_signup_body(method, identifier, uri, False, user)
            uri = MagicLink._compose_signup_url(method)
            self._auth_helper.do_post(uri, body)
            
    def sign_up_or_in(
        self, method: DeliveryMethod, identifier: str, uri: str
    ) -> None:
        if not self._auth_helper.verify_delivery_method(method, identifier):
            raise AuthException(
                500,
                "identifier failure",
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = MagicLink._compose_signin_body(identifier, uri, False)
        uri = MagicLink._compose_sign_up_or_in_url(method)
        self._auth_helper.do_post(uri, body)

    def verify(self, token: str) -> dict:
            uri = EndpointsV1.verifyMagicLinkAuthPath
            body = MagicLink._compose_verify_body(token)
            response = self._auth_helper.do_post(uri, body)
        
            resp = response.json()
            jwt_response = self._auth_helper._generate_jwt_response(
                resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
            )
            return jwt_response

    def update_user_email(self, identifier: str, email: str, refresh_token: str) -> None:
        if identifier == "":
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")


        AuthHelper.validate_email(email)
        
        body = MagicLink._compose_update_user_email_body(identifier, email)
        uri = EndpointsV1.updateUserEmailOTPPath
        self._auth_helper.do_post(uri, body, None, refresh_token)


    def update_user_phone(self, method: DeliveryMethod, identifier: str, phone: str, refresh_token: str) -> None:
        if identifier == "":
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")
        
        AuthHelper.validate_phone(method, phone)

        body = MagicLink._compose_update_user_phone_body(identifier, phone)
        uri = EndpointsV1.updateUserPhoneOTPPath
        self._auth_helper.do_post(uri, body, None, refresh_token)
    
    @staticmethod
    def _compose_signin_url(method: DeliveryMethod) -> str:
        return AuthHelper.compose_url(EndpointsV1.signInAuthMagicLinkPath, method)

    @staticmethod
    def _compose_signup_url(method: DeliveryMethod) -> str:
        return AuthHelper.compose_url(EndpointsV1.signUpAuthMagicLinkPath, method)
        
    @staticmethod
    def _compose_sign_up_or_in_url(method: DeliveryMethod) -> str:
        return AuthHelper.compose_url(EndpointsV1.signUpOrInAuthMagicLinkPath, method)

    @staticmethod
    def _compose_update_phone_url(method: DeliveryMethod) -> str:
        return AuthHelper.compose_url(EndpointsV1.updateUserPhoneMagicLinkPath, method)
    
    @staticmethod
    def _compose_signin_body(identifier: string, uri: string, cross_device: bool) -> dict:
        return {
            "externalId": identifier,
            "URI": uri,
            "crossDevice": cross_device,
        }
    
    @staticmethod
    def _compose_signup_body(method: DeliveryMethod, identifier: string, uri: string, cross_device: bool, user: dict=None) -> dict:
        body = {
            "externalId": identifier,
            "URI": uri,
            "crossDevice": cross_device,
        }

        if user is not None:
            body["user"] = user
            method_str, val = AuthHelper.get_identifier_by_method(method, user)
            body[method_str] = val
        return body

    @staticmethod
    def _compose_verify_body(token: string) -> dict:
        return {
            "token": token,
        }
        
    @staticmethod
    def _compose_update_user_email_body(identifier: str, email: str) -> dict:
        return {
            "externalId": identifier,
            "email": email
        }

    @staticmethod
    def _compose_update_user_phone_body(identifier: str, phone: str) -> dict:
        return {
            "externalId": identifier,
            "phone": phone
        }

