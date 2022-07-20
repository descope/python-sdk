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
    DeliveryMethod,
    EndpointsV1,
    SESSION_COOKIE_NAME,
)
from descope.exceptions import AuthException


class AuthHelper:
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
                    "Failed to init AuthHelper object, project should not be empty, remember to set env variable DESCOPE_PROJECT_ID or pass along it to init funcation",
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

    def do_get(self, uri: str, cookies=None, params=None, allow_redirects=None) -> requests.Response:
        response = requests.get(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self._get_default_headers(),
            cookies=cookies,
            params=params,
            allow_redirects=allow_redirects,
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.text)
        return response

    def do_post(self, uri: str, body: dict, cookies=None, pswd: str=None) -> requests.Response:
        response = requests.post(
            f"{DEFAULT_BASE_URI}{uri}",
            headers=self._get_default_headers(pswd),
            data=json.dumps(body),
            cookies=cookies,
        )
        if not response.ok:
            raise AuthException(response.status_code, "", response.text)
        return response

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

        alg = public_key.get(AuthHelper.ALGORITHM_KEY, None)
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
                loaded_kid, pub_key, alg = AuthHelper._validate_and_load_public_key(key)
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
    def _get_identifier_by_method(
        method: DeliveryMethod, user: dict
    ) -> Tuple[str, str]:
        if method is DeliveryMethod.EMAIL:
            email = user.get("email", "")
            return "email", email
        elif method is DeliveryMethod.PHONE:
            phone = user.get("phone", "")
            return "phone", phone
        elif method is DeliveryMethod.WHATSAPP:
            whatsapp = user.get("phone", "")
            return ("whatsapp", whatsapp)
        else:
            raise AuthException(
                500, "identifier failure", f"Unknown delivery method {method}"
            )

    def _generate_auth_info(self, response_body, cookie) -> dict:
        tokens = {}
        for token in response_body["jwts"]:
            token_claims = self._validate_and_load_tokens(token, None)
            token_claims["projectId"] = token_claims.pop(
                "iss"
            )  # replace the key name from iss->projectId
            token_claims["userId"] = token_claims.pop(
                "sub"
            )  # replace the key name from sub->userId
            tokens[token_claims["cookieName"]] = token_claims

        if cookie:
            token_claims = self._validate_and_load_tokens(cookie, None)
            token_claims["projectId"] = token_claims.pop(
                "iss"
            )  # replace the key name from iss->projectId
            token_claims["userId"] = token_claims.pop(
                "sub"
            )  # replace the key name from sub->userId
            tokens[token_claims["cookieName"]] = token_claims

        return tokens

    def _generate_jwt_response(self, response_body, cookie) -> dict:
        tokens = self._generate_auth_info(response_body, cookie)
        jwt_response = {
            "error": response_body.get("error", ""),
            "jwts": tokens,
            "user": response_body.get("user", ""),
            "firstSeen": response_body.get("firstSeen", True),
        }
        return jwt_response

    def _get_default_headers(self, pswd: str=None):
        headers = {}
        headers["Content-Type"] = "application/json"

        if pswd:
            bytes = f"{self.project_id}:{pswd}".encode("ascii")
        else:
            bytes = f"{self.project_id}:".encode("ascii")
        headers["Authorization"] = f"Basic {base64.b64encode(bytes).decode('ascii')}"
        return headers

    def _validate_and_load_tokens(
        self, signed_token: str, signed_refresh_token: str
    ) -> dict:
        if signed_token is None:
            raise AuthException(
                401,
                "token validation failure",
                f"signed token {signed_token} is empty",
            )

        try:
            unverified_header = jwt.get_unverified_header(signed_token)
        except Exception as e:
            raise AuthException(
                401, "token validation failure", f"Failed to parse token header, {e}"
            )

        alg_header = unverified_header.get(AuthHelper.ALGORITHM_KEY, None)
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

            claims["jwt"] = signed_token
            return claims

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
            auth_info = self.refresh_token(signed_token, signed_refresh_token)

            claims = auth_info[SESSION_COOKIE_NAME]
            return claims

        except Exception as e:
            raise AuthException(
                401, "token validation failure", f"token is not valid, {e}"
            )

