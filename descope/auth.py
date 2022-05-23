import base64
import json
import os
import re
from threading import RLock
from typing import Tuple

import jwt
import requests
from email_validator import EmailNotValidError, validate_email
from requests.cookies import RequestsCookieJar  # noqa: F401
from requests.models import Response  # noqa: F401

from descope.common import (
    DEFAULT_BASE_URI,
    DEFAULT_FETCH_PUBLIC_KEY_URI,
    PHONE_REGEX,
    DeliveryMethod,
    EndpointsV1,
    User,
)
from descope.exceptions import AuthException


class AuthClient:
    def __init__(self, project_id: str, public_key: str = None):
        self.lock_public_keys = RLock()
        # validate project id
        if project_id is None or project_id == "":
            # try get the project_id from env
            project_id = os.getenv("DESCOPE_PROJECT_ID", "")
            if project_id == "":
                raise AuthException(
                    500,
                    "Init failure",
                    "Failed to init AuthClient object, project should not be empty",
                )
        self.project_id = project_id

        if public_key is None or public_key == "":
            public_key = os.getenv("DESCOPE_PUBLIC_KEY", None)

        with self.lock_public_keys:
            if public_key is None or public_key == "":
                self.public_keys = {}  # public key will be fetched later (on demand)
            else:
                kid, pub_key = self._validate_and_load_public_key(public_key)
                self.public_keys = {kid: pub_key}

    @staticmethod
    def _validate_and_load_public_key(public_key) -> Tuple[str, jwt.PyJWK]:
        if isinstance(public_key, str):
            try:
                public_key = json.loads(public_key)
            except Exception as e:
                raise AuthException(
                    500,
                    "Public key failure",
                    f"Failed to load public key, invalid public key, err: {e}",
                )

        if not isinstance(public_key, dict):
            raise AuthException(
                500,
                "Public key failure",
                "Failed to load public key, invalid public key (unknown type)",
            )

        kid = public_key.get("kid", None)
        if kid is None:
            raise AuthException(
                500,
                "Public key failure",
                "Failed to load public key, missing kid property",
            )
        try:
            # Load and validate public key
            return (kid, jwt.PyJWK(public_key))
        except jwt.InvalidKeyError as e:
            raise AuthException(
                500,
                "Public key failure",
                f"Failed to load public key {e}",
            )
        except jwt.PyJWKError as e:
            raise AuthException(
                500,
                "Public key failure",
                f"Failed to load public key {e}",
            )

    def _fetch_public_keys(self) -> None:
        response = requests.get(
            f"{DEFAULT_FETCH_PUBLIC_KEY_URI}{EndpointsV1.publicKeyPath}/{self.project_id}",
            headers=self._get_default_headers(),
        )

        if not response.ok:
            raise AuthException(
                401, "public key fetching failed", f"err: {response.reason}"
            )

        jwks_data = response.text
        try:
            jwkeys = json.loads(jwks_data)
        except Exception as e:
            raise AuthException(
                401, "public key fetching failed", f"Failed to load jwks {e}"
            )

        with self.lock_public_keys:
            # Load all public keys for this project
            self.public_keys = {}
            for key in jwkeys:
                try:
                    loaded_kid, pub_key = AuthClient._validate_and_load_public_key(key)
                    self.public_keys[loaded_kid] = pub_key
                except Exception:
                    # just continue to the next key
                    pass

    @staticmethod
    def _verify_delivery_method(method: DeliveryMethod, identifier: str) -> bool:
        if identifier == "" or identifier is None:
            return False

        if method == DeliveryMethod.EMAIL:
            try:
                validate_email(identifier)
                return True
            except EmailNotValidError:
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
        return AuthClient._compose_url(EndpointsV1.signInAuthOTPPath, method)

    @staticmethod
    def _compose_signup_url(method: DeliveryMethod) -> str:
        return AuthClient._compose_url(EndpointsV1.signUpAuthOTPPath, method)

    @staticmethod
    def _compose_verify_code_url(method: DeliveryMethod) -> str:
        return AuthClient._compose_url(EndpointsV1.verifyCodeAuthPath, method)

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
            raise AuthException(response.status_code, "", response.text)

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
                f"Failed to parse token header, {e}",
            )

        kid = unverified_header.get("kid", None)
        if kid is None:
            raise AuthException(
                401,
                "token validation failure",
                "Token header is missing kid property",
            )

        with self.lock_public_keys:
            if self.public_keys == {} or self.public_keys.get(kid, None) is None:
                self._fetch_public_keys()

            found_key = self.public_keys.get(kid, None)
            if found_key is None:
                raise AuthException(
                    401,
                    "public key validation failed",
                    "Failed to validate public key, public key not found",
                )
            # copy the key so we can release the lock
            # copy_key = deepcopy(found_key)
            copy_key = found_key

        try:
            jwt.decode(jwt=signed_token, key=copy_key.key, algorithms=["ES384"])
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
