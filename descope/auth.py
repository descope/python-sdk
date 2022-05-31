import base64
import json
import os
import re
from threading import Lock
from typing import Tuple

import jwt
import requests
from email_validator import EmailNotValidError, validate_email
from jwt.exceptions import ExpiredSignatureError
from requests.cookies import RequestsCookieJar  # noqa: F401
from requests.models import Response  # noqa: F401

from descope.common import (
    DEFAULT_BASE_URI,
    DEFAULT_FETCH_PUBLIC_KEY_URI,
    PHONE_REGEX,
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
    User,
)
from descope.exceptions import AuthException


class AuthClient:
    ALGORITHM_KEY = "alg"

    def __init__(self, project_id: str, public_key: str = None):
        self.lock_public_keys = Lock()
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
                self.public_keys = {}
            else:
                kid, pub_key, alg = self._validate_and_load_public_key(public_key)
                self.public_keys = {kid: (pub_key, alg)}

    @staticmethod
    def _validate_and_load_public_key(public_key) -> Tuple[str, jwt.PyJWK, str]:
        if isinstance(public_key, str):
            try:
                public_key = json.loads(public_key)
            except Exception as e:
                raise AuthException(
                    400,
                    "Public key failure",
                    f"Failed to load public key, invalid public key, err: {e}",
                )

        if not isinstance(public_key, dict):
            raise AuthException(
                400,
                "Public key failure",
                "Failed to load public key, invalid public key (unknown type)",
            )

        alg = public_key.get(AuthClient.ALGORITHM_KEY, None)
        if alg is None:
            raise AuthException(
                400,
                "Public key failure",
                "Failed to load public key, missing alg property",
            )

        kid = public_key.get("kid", None)
        if kid is None:
            raise AuthException(
                400,
                "Public key failure",
                "Failed to load public key, missing kid property",
            )
        try:
            # Load and validate public key
            return (kid, jwt.PyJWK(public_key), alg)
        except jwt.InvalidKeyError as e:
            raise AuthException(
                400,
                "Public key failure",
                f"Failed to load public key {e}",
            )
        except jwt.PyJWKError as e:
            raise AuthException(
                400,
                "Public key failure",
                f"Failed to load public key {e}",
            )

    def _fetch_public_keys(self) -> None:

        # This function called under mutex protection so no need to acquire it once again

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

        # Load all public keys for this project
        self.public_keys = {}
        for key in jwkeys:
            try:
                loaded_kid, pub_key, alg = AuthClient._validate_and_load_public_key(key)
                self.public_keys[loaded_kid] = (pub_key, alg)
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
    def _compose_refresh_token_url() -> str:
        return EndpointsV1.refreshTokenPath

    @staticmethod
    def _compose_logout_url() -> str:
        return EndpointsV1.logoutPath

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

    def sign_up_otp(
        self, method: DeliveryMethod, identifier: str, user: User = None
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

        if not self._verify_delivery_method(method, identifier):
            raise AuthException(
                500,
                "identifier failure",
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        body = {self._get_identifier_name_by_method(method): identifier}

        if user is not None:
            body["user"] = user.get_data()

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
    ) -> Tuple[dict, dict]:  # Tuple(dict of claims, dict of tokens)
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

        session_token = response.cookies.get(SESSION_COOKIE_NAME)
        refresh_token = response.cookies.get(REFRESH_SESSION_COOKIE_NAME)

        claims, tokens = self._validate_and_load_tokens(session_token, refresh_token)
        return (claims, tokens)

    def refresh_token(self, signed_token: str, signed_refresh_token: str) -> str:
        cookies = {
            SESSION_COOKIE_NAME: signed_token,
            REFRESH_SESSION_COOKIE_NAME: signed_refresh_token,
        }

        uri = AuthClient._compose_refresh_token_url()
        response = requests.get(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self._get_default_headers(),
            cookies=cookies,
        )

        if not response.ok:
            raise AuthException(
                response.status_code,
                "Refresh token failed",
                f"Failed to refresh token with error: {response.text}",
            )

        res_cookies = response.cookies
        ds_cookie = res_cookies.get(SESSION_COOKIE_NAME, None)
        if not ds_cookie:
            raise AuthException(
                401, "Refresh token failed", "Failed to get new refreshed token"
            )
        return ds_cookie

    def _validate_and_load_tokens(
        self, signed_token: str, signed_refresh_token: str
    ) -> Tuple[dict, dict]:  # Tuple(dict of claims, dict of tokens)

        if signed_token is None or signed_refresh_token is None:
            raise AuthException(
                401,
                "token validation failure",
                f"signed token {signed_token} or/and signed refresh token {signed_refresh_token} are empty",
            )

        try:
            unverified_header = jwt.get_unverified_header(signed_token)
        except Exception as e:
            raise AuthException(
                401, "token validation failure", f"Failed to parse token header, {e}"
            )

        alg_header = unverified_header.get(AuthClient.ALGORITHM_KEY, None)
        if alg_header is None or alg_header == "none":
            raise AuthException(
                401, "token validation failure", "Token header is missing alg property"
            )

        kid = unverified_header.get("kid", None)
        if kid is None:
            raise AuthException(
                401, "token validation failure", "Token header is missing kid property"
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
            # save reference to the founded key
            # (as another thread can change the self.public_keys dict)
            copy_key = found_key

        alg_from_key = copy_key[1]
        if alg_header != alg_from_key:
            raise AuthException(
                401,
                "token validation failure",
                "header algorithm is not matched key algorithm",
            )

        try:
            claims = jwt.decode(
                jwt=signed_token, key=copy_key[0].key, algorithms=[alg_header]
            )
            tokens = {
                SESSION_COOKIE_NAME: signed_token,
                REFRESH_SESSION_COOKIE_NAME: signed_refresh_token,
            }
            return (claims, tokens)
        except ExpiredSignatureError:
            # Session token expired, check that refresh token is valid
            try:
                jwt.decode(
                    jwt=signed_refresh_token,
                    key=copy_key[0].key,
                    algorithms=[alg_header],
                )
            except Exception as e:
                raise AuthException(
                    401, "token validation failure", f"refresh token is not valid, {e}"
                )
            # Refresh token is valid now refresh the session token
            refreshed_session_token = self.refresh_token(
                signed_token, signed_refresh_token
            )
            # Parse the new session token
            try:
                claims = jwt.decode(
                    jwt=refreshed_session_token,
                    key=copy_key[0].key,
                    algorithms=[alg_header],
                )
                tokens = {
                    SESSION_COOKIE_NAME: refreshed_session_token,
                    REFRESH_SESSION_COOKIE_NAME: signed_refresh_token,
                }
                return (claims, tokens)
            except Exception as e:
                raise AuthException(
                    401,
                    "token validation failure",
                    f"new session token is not valid, {e}",
                )
        except Exception as e:
            raise AuthException(
                401, "token validation failure", f"token is not valid, {e}"
            )

    def validate_session_request(
        self, signed_token: str, signed_refresh_token: str
    ) -> Tuple[dict, dict]:  # Tuple(dict of claims, dict of tokens)
        """
        Validate session request by verify the session JWT session token
        and session refresh token in case it expired

        Args:
        signed_token (str): The session JWT token to get its signature verified

        signed_refresh_token (str): The session refresh JWT token that will be
        use to refresh the session token (if expired)

        Return value (Tuple[dict, dict]):
        Return two dicts where the first contains the jwt claims data and
        second contains the existing signed token (or the new signed
        token in case the old one expired) and refreshed session token

        Raise:
        AuthException: for any case token is not valid means session is not
        authorized
        """
        return self._validate_and_load_tokens(signed_token, signed_refresh_token)

    def logout(
        self, signed_token: str, signed_refresh_token: str
    ) -> requests.cookies.RequestsCookieJar:
        uri = AuthClient._compose_logout_url()
        cookies = {
            SESSION_COOKIE_NAME: signed_token,
            REFRESH_SESSION_COOKIE_NAME: signed_refresh_token,
        }

        response = requests.get(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self._get_default_headers(),
            cookies=cookies,
        )

        if not response.ok:
            raise AuthException(
                response.status_code,
                "Failed logout",
                f"logout request failed with error {response.text}",
            )

        return response.cookies

    def _get_default_headers(self):
        headers = {}
        headers["Content-Type"] = "application/json"

        bytes = f"{self.project_id}:".encode("ascii")
        headers["Authorization"] = f"Basic {base64.b64encode(bytes).decode('ascii')}"
        return headers
