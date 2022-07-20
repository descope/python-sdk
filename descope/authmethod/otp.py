import requests
import json
import re

from email_validator import EmailNotValidError, validate_email

from descope.common import (
    DEFAULT_BASE_URI,
    DEFAULT_FETCH_PUBLIC_KEY_URI,
    PHONE_REGEX,
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
)
from descope.exceptions import AuthException

class OTP():
    client = None

    def __init__(self, client):
        self.client = client
    
    
    def _compose_signin_url(self, method: DeliveryMethod) -> str:
        return self.client.compose_url(EndpointsV1.signInAuthOTPPath, method)

    def _compose_signup_url(self, method: DeliveryMethod) -> str:
        return self.client.compose_url(EndpointsV1.signUpAuthOTPPath, method)

    def _compose_verify_code_url(self, method: DeliveryMethod) -> str:
        return self.client._compose_url(EndpointsV1.verifyCodeAuthPath, method)


    def sign_up(
        self, method: DeliveryMethod, identifier: str, user: dict = None
    ) -> None:
        """
        Sign up a new user by OTP

        Args:
        method (DeliveryMethod): The OTP method you would like to verify the code
        sent to you (by the same delivery method)

        identifier (str): The identifier based on the chosen delivery method,
        For email it should be the email address.
        For phone it should be the phone number you would like to get the code
        For whatsapp it should be the phone number you would like to get the code

        Raise:
        AuthException: for any case sign up by otp operation failed
        """

        if not self.client._verify_delivery_method(method, identifier):
            raise AuthException(
                500,
                "identifier failure",
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = {"externalId": identifier}

        if user is not None:
            body["user"] = user
            method_str, val = self.client._get_identifier_by_method(method, user)
            body[method_str] = val

        uri = self._compose_signup_url(method)
        response = requests.post(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self.client._get_default_headers(),
            data=json.dumps(body),
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.reason)

    def sign_in(self, method: DeliveryMethod, identifier: str) -> None:
        """
        Sign in a user by OTP

        Args:
        method (DeliveryMethod): The OTP method you would like to verify the code
        sent to you (by the same delivery method)

        identifier (str): The identifier based on the chosen delivery method,
        For email it should be the email address.
        For phone it should be the phone number you would like to get the code
        For whatsapp it should be the phone number you would like to get the code

        Raise:
        AuthException: for any case sign up by otp operation failed
        """

        if not self.client._verify_delivery_method(method, identifier):
            raise AuthException(
                500,
                "identifier failure",
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = {
            "externalId": identifier,
        }

        uri = self._compose_signin_url(method)
        response = requests.post(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self.client._get_default_headers(),
            data=json.dumps(body),
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.text)

    def sign_up_or_in(self, method: DeliveryMethod, identifier: str) -> None:
        return self.sign_in(method, identifier)

    def verify_code(self, method: DeliveryMethod, identifier: str, code: str) -> dict:
        """Verify OTP code sent by the delivery method that chosen

        Args:
        method (DeliveryMethod): The OTP method you would like to verify the code
        sent to you (by the same delivery method)

        identifier (str): The identifier based on the chosen delivery method,
        For email it should be the email address.
        For phone it should be the phone number you would like to get the code
        For whatsapp it should be the phone number you would like to get the code

        code (str): The authorization code you get by the delivery method during signup/signin

        Return value (Tuple[dict, dict]):
        Return two dicts where the first contains the jwt claims data and
        second contains the existing signed token (or the new signed
        token in case the old one expired) and refreshed session token

        Raise:
        AuthException: for any case code is not valid or tokens verification failed
        """

        if not self.client._verify_delivery_method(method, identifier):
            raise AuthException(
                500,
                "identifier failure",
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = {"externalId": identifier, "code": code}

        uri = self._compose_verify_code_url(method)
        response = requests.post(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self.client._get_default_headers(),
            data=json.dumps(body),
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.reason)

        resp = response.json()
        jwt_response = self._generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response


    def update_user_email(self, identifier: str, email: str, refresh_token: str) -> None:
        if identifier == "":
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        if email == "":
            raise AuthException(500, "Invalid argument", "email cannot be empty")

        try:
            validate_email(email)
        except EmailNotValidError as ex:
            raise AuthException(500, "Invalid argument", f"Email address is not valid: {ex}")

        body = {
            "externalId": identifier,
            "email": email
        }

        uri = f"{DEFAULT_BASE_URI}{EndpointsV1.updateUserEmailOTPPath}"
        response = requests.post(
            uri,
            headers=self.client._get_default_headers(refresh_token),
            data=json.dumps(body),
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.text)


    def update_user_phone(self, method: DeliveryMethod, identifier: str, phone: str, refresh_token: str) -> None:
        if identifier == "":
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        if phone == "":
            raise AuthException(500, "Invalid argument", "Phone cannot be empty")

        if not re.match(PHONE_REGEX, phone):
            raise AuthException(500, "Invalid argument", f"Phone number not valid")

        if method != DeliveryMethod.PHONE and method == DeliveryMethod.WHATSAPP:
            raise AuthException(500, "Invalid argument", f"Invalid method supplied")

        body = {
            "externalId": identifier,
            "phone": phone
        }

        uri = f"{DEFAULT_BASE_URI}{EndpointsV1.updateUserPhoneOTPPath}"
        response = requests.post(
            uri,
            headers=self.client._get_default_headers(refresh_token),
            data=json.dumps(body),
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.text)