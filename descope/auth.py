import base64
import json
import os
import re

import jwt
import requests
from requests.cookies import RequestsCookieJar  # noqa: F401
from requests.models import Response  # noqa: F401

from descope.common import (
    DEFAULT_BASE_URI,
    EMAIL_REGEX,
    PHONE_REGEX,
    SIGNIN_OTP_PATH,
    SIGNUP_OTP_PATH,
    VERIFY_CODE_PATH,
    DeliveryMethod,
    User,
)
from descope.exceptions import AuthException


class AuthClient:
    def __init__(self, project_id: str, public_key: str):

        # validate project id
        if project_id is None or project_id == "":
            # try get the project_id from env
            project_id = os.getenv("DESCOPE_PROJECT_ID", "")
            if project_id == "":
                raise AuthException(
                    500,
                    "Init failure",
                    "Failed to init AuthClient object, project id is empty",
                )
        self.project_id = project_id

        if public_key is None or public_key == "":
            public_key = os.getenv("DESCOPE_PUBLIC_KEY", "")
            if public_key == "":
                raise AuthException(
                    500,
                    "Init failure",
                    "Failed to init AuthClient object, public key cannot be found",
                )

        if isinstance(public_key, str):
            try:
                public_key = json.loads(public_key)
            except Exception as e:
                raise AuthException(
                    500,
                    "Init failure",
                    f"Failed to init AuthClient object, invalid public key, err: {e}",
                )

        if not isinstance(public_key, dict):
            raise AuthException(
                500,
                "Init failure",
                "Failed to init AuthClient object, invalid public key (unknown type)",
            )

        try:
            # Load and validate public key
            self.public_key = jwt.PyJWK(public_key)
        except jwt.InvalidKeyError as e:
            raise AuthException(
                500,
                "Init failure",
                f"Failed to init AuthClient object, failed to load public key {e}",
            )
        except jwt.PyJWKError as e:
            raise AuthException(
                500,
                "Init failure",
                f"Failed to init AuthClient object, failed to load public key {e}",
            )

    @staticmethod
    def _verify_delivery_method(method: DeliveryMethod, identifier: str) -> bool:
        if identifier == "" or identifier is None:
            return False

        if method == DeliveryMethod.EMAIL:
            if not re.match(EMAIL_REGEX, identifier):
                return False
        elif method == DeliveryMethod.PHONE:
            if not re.match(PHONE_REGEX, identifier):
                return False
        elif method == DeliveryMethod.WHATSAPP:
            if not re.match(PHONE_REGEX, identifier):
                return False
        else:
            return False

        return True

    @staticmethod
    def _compose_url(base: str, method: DeliveryMethod) -> str:
        suffix = ""
        if method is DeliveryMethod.EMAIL:
            suffix = "email"
        elif method is DeliveryMethod.PHONE:
            suffix = "sms"
        elif method is DeliveryMethod.WHATSAPP:
            suffix = "whatsapp"
        else:
            raise AuthException(
                500, "url composing failure", f"Unknown delivery method {method}"
            )

        return f"{base}/{suffix}"

    @staticmethod
    def _compose_signin_url(method: DeliveryMethod) -> str:
        return AuthClient._compose_url(SIGNIN_OTP_PATH, method)

    @staticmethod
    def _compose_signup_url(method: DeliveryMethod) -> str:
        return AuthClient._compose_url(SIGNUP_OTP_PATH, method)

    @staticmethod
    def _compose_verify_code_url(method: DeliveryMethod) -> str:
        return AuthClient._compose_url(VERIFY_CODE_PATH, method)

    @staticmethod
    def _get_identifier_name_by_method(method: DeliveryMethod) -> str:
        if method is DeliveryMethod.EMAIL:
            return "email"
        elif method is DeliveryMethod.PHONE:
            return "phone"
        elif method is DeliveryMethod.WHATSAPP:
            return "phone"
        else:
            raise AuthException(
                500, "identifier failure", f"Unknown delivery method {method}"
            )

    def sign_up_otp(self, method: DeliveryMethod, identifier: str, user: User) -> None:
        """
        DOC
        """

        if not self._verify_delivery_method(method, identifier):
            raise AuthException(
                500,
                "identifier failure",
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = {
            self._get_identifier_name_by_method(method): identifier,
            "user": user.get_data(),
        }

        uri = AuthClient._compose_signup_url(method)
        response = requests.post(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self._get_default_headers(),
            data=json.dumps(body),
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.reason)

    def sign_in_otp(self, method: DeliveryMethod, identifier: str) -> None:
        """
        DOC
        """

        if not self._verify_delivery_method(method, identifier):
            raise AuthException(
                500,
                "identifier failure",
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = {
            self._get_identifier_name_by_method(method): identifier,
        }

        uri = AuthClient._compose_signin_url(method)
        response = requests.post(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self._get_default_headers(),
            data=json.dumps(body),
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.reason)

    def verify_code(
        self, method: DeliveryMethod, identifier: str, code: str
    ) -> requests.cookies.RequestsCookieJar:
        """
        DOC
        """

        if not self._verify_delivery_method(method, identifier):
            raise AuthException(
                500,
                "identifier failure",
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = {self._get_identifier_name_by_method(method): identifier, "code": code}

        uri = AuthClient._compose_verify_code_url(method)
        response = requests.post(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self._get_default_headers(),
            data=json.dumps(body),
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.reason)
        return response.cookies

    def validate_session_request(self, signed_token):
        """
        DOC
        """
        try:
            unverified_header = jwt.get_unverified_header(signed_token)
        except Exception as e:
            raise AuthException(
                401,
                "token validation failure",
                f"Failed to get unverified token header, {e}",
            )
        token_type = unverified_header.get("typ", None)
        alg = unverified_header.get("alg", None)
        if token_type is None or alg is None:
            raise AuthException(
                401,
                "token validation failure",
                f"Token header is missing token type or algorithm, token_type={token_type} alg={alg}",
            )

        try:
            jwt.decode(jwt=signed_token, key=self.public_key.key, algorithms=["ES384"])
        except Exception as e:
            raise AuthException(
                401, "token validation failure", f"token is not valid, {e}"
            )

    def _get_default_headers(self):
        headers = {}
        headers["Content-Type"] = "application/json"

        bytes = f"{self.project_id}:".encode("ascii")
        headers["Authorization"] = f"Basic {base64.b64encode(bytes).decode('ascii')}"
        return headers
