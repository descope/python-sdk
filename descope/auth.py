import json
import os
import re
from threading import Lock
from typing import Tuple

import jwt
import requests
from email_validator import EmailNotValidError, validate_email
from jwt.exceptions import ExpiredSignatureError

from descope.common import (
    COOKIE_DATA_NAME,
    DEFAULT_BASE_URL,
    PHONE_REGEX,
    REFRESH_SESSION_COOKIE_NAME,
    REFRESH_SESSION_TOKEN_NAME,
    SESSION_TOKEN_NAME,
    DeliveryMethod,
    EndpointsV1,
)
from descope.exceptions import (
    ERROR_TYPE_INVALID_ARGUMENT,
    ERROR_TYPE_INVALID_PUBLIC_KEY,
    ERROR_TYPE_INVALID_TOKEN,
    ERROR_TYPE_SERVER_ERROR,
    AuthException,
)


class Auth:
    ALGORITHM_KEY = "alg"

    def __init__(
        self,
        project_id: str = None,
        public_key: str = None,
        skip_verify: bool = False,
    ):
        self.lock_public_keys = Lock()
        # validate project id
        if not project_id:
            # try get the project_id from env
            project_id = os.getenv("DESCOPE_PROJECT_ID", "")
            if project_id == "":
                raise AuthException(
                    400,
                    ERROR_TYPE_INVALID_ARGUMENT,
                    "Unable to init Auth object because project_id cannot be empty. Set environment variable DESCOPE_PROJECT_ID or pass your Project ID to the init function.",
                )
        self.project_id = project_id

        self.secure = True
        if skip_verify:
            self.secure = False

        self.base_url = os.getenv("DESCOPE_BASE_URI", None) or DEFAULT_BASE_URL

        if not public_key:
            public_key = os.getenv("DESCOPE_PUBLIC_KEY", None)

        with self.lock_public_keys:
            if not public_key:
                self.public_keys = {}
            else:
                kid, pub_key, alg = self._validate_and_load_public_key(public_key)
                self.public_keys = {kid: (pub_key, alg)}

    def do_get(
        self,
        uri: str,
        params=None,
        allow_redirects=None,
        pswd: str = None,
    ) -> requests.Response:
        response = requests.get(
            f"{self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            params=params,
            allow_redirects=allow_redirects,
            verify=self.secure,
        )
        if not response.ok:
            raise AuthException(
                response.status_code, ERROR_TYPE_SERVER_ERROR, response.text
            )
        return response

    def do_post(self, uri: str, body: dict, pswd: str = None) -> requests.Response:
        response = requests.post(
            f"{self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            data=json.dumps(body),
            verify=self.secure,
        )
        if not response.ok:
            raise AuthException(
                response.status_code, ERROR_TYPE_SERVER_ERROR, response.text
            )
        return response

    def exchange_token(self, uri, code: str) -> dict:
        if not code:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "exchange code is empty",
            )

        params = Auth._compose_exchange_params(code)
        response = self.do_get(uri, params, False)
        resp = response.json()
        jwt_response = self.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    @staticmethod
    def verify_delivery_method(
        method: DeliveryMethod, identifier: str, user: dict
    ) -> bool:
        if not identifier:
            return False

        if not user or not isinstance(user, dict):
            return False

        if method == DeliveryMethod.EMAIL:
            if not user.get("email", None):
                user["email"] = identifier
            try:
                validate_email(user["email"])
                return True
            except EmailNotValidError:
                return False
        elif method == DeliveryMethod.PHONE:
            if not user.get("phone", None):
                user["phone"] = identifier
            if not re.match(PHONE_REGEX, user["phone"]):
                return False
        elif method == DeliveryMethod.WHATSAPP:
            if not user.get("phone", None):
                user["phone"] = identifier
            if not re.match(PHONE_REGEX, user["phone"]):
                return False
        else:
            return False

        return True

    @staticmethod
    def compose_url(base: str, method: DeliveryMethod) -> str:
        suffix = ""
        if method is DeliveryMethod.EMAIL:
            suffix = "email"
        elif method is DeliveryMethod.PHONE:
            suffix = "sms"
        elif method is DeliveryMethod.WHATSAPP:
            suffix = "whatsapp"
        else:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, f"Unknown delivery method: {method}"
            )

        return f"{base}/{suffix}"

    @staticmethod
    def get_identifier_by_method(method: DeliveryMethod, user: dict) -> Tuple[str, str]:
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
                400, ERROR_TYPE_INVALID_ARGUMENT, f"Unknown delivery method: {method}"
            )

    @staticmethod
    def validate_email(email: str):
        if email == "":
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "email address argument cannot be empty",
            )

        try:
            validate_email(email)
        except EmailNotValidError as ex:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, f"Invalid email address: {ex}"
            )

    @staticmethod
    def validate_phone(method: DeliveryMethod, phone: str):
        if phone == "":
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "Phone number argument cannot be empty",
            )

        if not re.match(PHONE_REGEX, phone):
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Invalid phone number"
            )

        if method != DeliveryMethod.PHONE and method != DeliveryMethod.WHATSAPP:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Invalid delivery method"
            )

    def refresh_token(self, refresh_token: str) -> dict:
        uri = Auth._compose_refresh_token_url()
        response = self.do_get(uri, None, None, refresh_token)

        resp = response.json()
        return self._generate_auth_info(resp, refresh_token)

    @staticmethod
    def _compose_exchange_params(code: str) -> dict:
        return {"code": code}

    @staticmethod
    def _validate_and_load_public_key(public_key) -> Tuple[str, jwt.PyJWK, str]:
        if isinstance(public_key, str):
            try:
                public_key = json.loads(public_key)
            except Exception as e:
                raise AuthException(
                    500,
                    ERROR_TYPE_INVALID_PUBLIC_KEY,
                    f"Unable to load public key. error: {e}",
                )

        if not isinstance(public_key, dict):
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                "Unable to load public key. Invalid public key error: (unknown type)",
            )

        alg = public_key.get(Auth.ALGORITHM_KEY, None)
        if alg is None:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                "Unable to load public key. Missing property: alg",
            )

        kid = public_key.get("kid", None)
        if kid is None:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                "Unable to load public key. Missing property: kid",
            )
        try:
            # Load and validate public key
            return (kid, jwt.PyJWK(public_key), alg)
        except jwt.InvalidKeyError as e:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                f"Unable to load public key. Error: {e}",
            )
        except jwt.PyJWKError as e:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                f"Unable to load public key {e}",
            )

    def _fetch_public_keys(self) -> None:

        # This function called under mutex protection so no need to acquire it once again
        response = requests.get(
            f"{self.base_url}{EndpointsV1.publicKeyPath}/{self.project_id}",
            headers=self._get_default_headers(),
            verify=self.secure,
        )

        if not response.ok:
            raise AuthException(
                response.status_code,
                ERROR_TYPE_SERVER_ERROR,
                f"Error: {response.reason}",
            )

        jwks_data = response.text
        try:
            jwkeys = json.loads(jwks_data)
        except Exception as e:
            raise AuthException(
                500, ERROR_TYPE_INVALID_PUBLIC_KEY, f"Unable to load jwks. Error: {e}"
            )

        # Load all public keys for this project
        self.public_keys = {}
        for key in jwkeys:
            try:
                loaded_kid, pub_key, alg = Auth._validate_and_load_public_key(key)
                self.public_keys[loaded_kid] = (pub_key, alg)
            except Exception:
                # just continue to the next key
                pass

    def _generate_auth_info(self, response_body: dict, refresh_token: str) -> dict:
        jwt_response = {}
        st_jwt = response_body.get("sessionJwt", "")
        if st_jwt:
            jwt_response[SESSION_TOKEN_NAME] = self._validate_token(st_jwt)
        rt_jwt = response_body.get("refreshJwt", "")
        if refresh_token:
            jwt_response[REFRESH_SESSION_TOKEN_NAME] = self._validate_token(
                refresh_token
            )
        elif rt_jwt:
            jwt_response[REFRESH_SESSION_TOKEN_NAME] = self._validate_token(rt_jwt)

        jwt_response[COOKIE_DATA_NAME] = {
            "exp": response_body.get("cookieExpiration", 0),
            "maxAge": response_body.get("cookieMaxAge", 0),
            "domain": response_body.get("cookieDomain", ""),
            "path": response_body.get("cookiePath", "/"),
        }

        return jwt_response

    def generate_jwt_response(self, response_body: dict, refresh_cookie: str) -> dict:
        jwt_response = self._generate_auth_info(response_body, refresh_cookie)

        projectId = jwt_response.get(SESSION_TOKEN_NAME, {}).get(
            "iss", None
        ) or jwt_response.get(REFRESH_SESSION_TOKEN_NAME, {}).get("iss", None)
        user_id = jwt_response.get(SESSION_TOKEN_NAME, {}).get(
            "sub", None
        ) or jwt_response.get(REFRESH_SESSION_TOKEN_NAME, {}).get("sub", None)

        jwt_response["tenants"] = response_body.get("tenants", {})
        jwt_response["projectId"] = projectId
        jwt_response["userId"] = user_id
        jwt_response["user"] = response_body.get("user", {})
        jwt_response["firstSeen"] = response_body.get("firstSeen", True)
        return jwt_response

    def _get_default_headers(self, pswd: str = None):
        headers = {}
        headers["Content-Type"] = "application/json"

        bearer = self.project_id
        if pswd:
            bearer = f"{self.project_id}:{pswd}"
        headers["Authorization"] = f"Bearer {bearer}"
        return headers

    # Validate a token and load the public key if needed
    def _validate_token(self, token: str) -> dict:
        if not token:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_TOKEN,
                "Token validation received empty token",
            )
        try:
            unverified_header = jwt.get_unverified_header(token)
        except Exception as e:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_TOKEN,
                f"Unable to parse token header. Error: {e}",
            )

        alg_header = unverified_header.get(Auth.ALGORITHM_KEY, None)
        if alg_header is None or alg_header == "none":
            raise AuthException(
                500, ERROR_TYPE_INVALID_TOKEN, "Token header is missing property: alg"
            )

        kid = unverified_header.get("kid", None)
        if kid is None:
            raise AuthException(
                500, ERROR_TYPE_INVALID_TOKEN, "Token header is missing property: kid"
            )

        with self.lock_public_keys:
            if self.public_keys == {} or self.public_keys.get(kid, None) is None:
                self._fetch_public_keys()

            found_key = self.public_keys.get(kid, None)
            if found_key is None:
                raise AuthException(
                    500,
                    ERROR_TYPE_INVALID_PUBLIC_KEY,
                    "Unable to validate public key. Public key not found.",
                )
            # save reference to the founded key
            # (as another thread can change the self.public_keys dict)
            copy_key = found_key

        alg_from_key = copy_key[1]
        if alg_header != alg_from_key:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                "Algorithm signature in JWT header does not match the algorithm signature in the public key",
            )
        claims = jwt.decode(jwt=token, key=copy_key[0].key, algorithms=[alg_header])
        claims["jwt"] = token
        return claims

    def _validate_and_load_tokens(self, session_token: str, refresh_token: str) -> dict:
        if not session_token and not refresh_token:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_TOKEN,
                "Both refresh token and session token are empty",
            )

        if session_token:
            try:
                return self._validate_token(session_token)
            except ExpiredSignatureError:
                # Session token expired, check that refresh token is valid
                if refresh_token:
                    try:
                        self._validate_token(refresh_token)
                    except Exception as e:
                        raise AuthException(
                            401, ERROR_TYPE_INVALID_TOKEN, f"Invalid refresh token: {e}"
                        )
                else:
                    raise AuthException(
                        401,
                        ERROR_TYPE_INVALID_TOKEN,
                        "Session token expired and no refresh token provided",
                    )
                # Refresh token is valid now refresh the session token
                return self.refresh_token(refresh_token)  # return jwt_response dict
            except Exception as e:
                raise AuthException(
                    500, ERROR_TYPE_INVALID_TOKEN, f"Invalid token: {e}"
                )

        # If we got here, we did not have a session token so only do the refresh
        try:
            self._validate_token(refresh_token)
        except Exception as e:
            raise AuthException(
                401, ERROR_TYPE_INVALID_TOKEN, f"Invalid refresh token: {e}"
            )
        # Refresh token is valid now refresh the session token
        return self.refresh_token(refresh_token)  # return jwt_response dict

    @staticmethod
    def _compose_refresh_token_url() -> str:
        return EndpointsV1.refreshTokenPath
