import json
import os
import platform
import re
from threading import Lock
from typing import Tuple

import jwt
import pkg_resources
import requests
from email_validator import EmailNotValidError, validate_email

from descope.common import (
    COOKIE_DATA_NAME,
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT_SECONDS,
    PHONE_REGEX,
    REFRESH_SESSION_COOKIE_NAME,
    REFRESH_SESSION_TOKEN_NAME,
    SESSION_TOKEN_NAME,
    DeliveryMethod,
    EndpointsV1,
    EndpointsV2,
)
from descope.exceptions import (
    API_RATE_LIMIT_RETRY_AFTER_HEADER,
    ERROR_TYPE_API_RATE_LIMIT,
    ERROR_TYPE_INVALID_ARGUMENT,
    ERROR_TYPE_INVALID_PUBLIC_KEY,
    ERROR_TYPE_INVALID_TOKEN,
    ERROR_TYPE_SERVER_ERROR,
    AuthException,
    RateLimitException,
)


class Auth:
    ALGORITHM_KEY = "alg"

    def __init__(
        self,
        project_id: str = None,
        public_key: str = None,
        skip_verify: bool = False,
        management_key: str = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
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
        self.timeout_seconds = timeout_seconds

        if not management_key:
            management_key = os.getenv("DESCOPE_MANAGEMENT_KEY", None)
        self.management_key = management_key

        if not public_key:
            public_key = os.getenv("DESCOPE_PUBLIC_KEY", None)

        with self.lock_public_keys:
            if not public_key:
                self.public_keys = {}
            else:
                kid, pub_key, alg = self._validate_and_load_public_key(public_key)
                self.public_keys = {kid: (pub_key, alg)}

    def _raise_rate_limit_exception(self, response):
        resp = response.json()
        raise RateLimitException(
            resp.get("errorCode", "429"),
            ERROR_TYPE_API_RATE_LIMIT,
            resp.get("errorDescription", ""),
            resp.get("errorMessage", ""),
            rate_limit_parameters={
                API_RATE_LIMIT_RETRY_AFTER_HEADER: int(
                    response.headers.get(API_RATE_LIMIT_RETRY_AFTER_HEADER, 0)
                )
            },
        )

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
            timeout=self.timeout_seconds,
        )
        if not response.ok:
            if response.status_code == 429:
                self._raise_rate_limit_exception(response)  # Raise RateLimitException
            raise AuthException(
                response.status_code, ERROR_TYPE_SERVER_ERROR, response.text
            )
        return response

    def do_post(
        self, uri: str, body: dict, params=None, pswd: str = None
    ) -> requests.Response:
        response = requests.post(
            f"{self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            data=json.dumps(body),
            allow_redirects=False,
            verify=self.secure,
            params=params,
            timeout=self.timeout_seconds,
        )
        if not response.ok:
            if response.status_code == 429:
                self._raise_rate_limit_exception(response)  # Raise RateLimitException

            raise AuthException(
                response.status_code, ERROR_TYPE_SERVER_ERROR, response.text
            )
        return response

    def do_delete(self, uri: str, pswd: str = None) -> requests.Response:
        response = requests.delete(
            f"{self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            allow_redirects=False,
            verify=self.secure,
            timeout=self.timeout_seconds,
        )
        if not response.ok:
            if response.status_code == 429:
                self._raise_rate_limit_exception(response)  # Raise RateLimitException

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

        body = Auth._compose_exchange_body(code)
        response = self.do_post(uri, body, None)
        resp = response.json()
        jwt_response = self.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    @staticmethod
    def verify_delivery_method(
        method: DeliveryMethod, login_id: str, user: dict
    ) -> bool:
        if not login_id:
            return False

        if not isinstance(user, dict):
            return False

        if method == DeliveryMethod.EMAIL:
            if not user.get("email", None):
                user["email"] = login_id
            try:
                validate_email(email=user["email"], check_deliverability=False)
                return True
            except EmailNotValidError:
                return False
        elif method == DeliveryMethod.SMS:
            if not user.get("phone", None):
                user["phone"] = login_id
            if not re.match(PHONE_REGEX, user["phone"]):
                return False
        elif method == DeliveryMethod.WHATSAPP:
            if not user.get("phone", None):
                user["phone"] = login_id
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
        elif method is DeliveryMethod.SMS:
            suffix = "sms"
        elif method is DeliveryMethod.WHATSAPP:
            suffix = "whatsapp"
        else:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, f"Unknown delivery method: {method}"
            )

        return f"{base}/{suffix}"

    @staticmethod
    def get_login_id_by_method(method: DeliveryMethod, user: dict) -> Tuple[str, str]:
        if method is DeliveryMethod.EMAIL:
            email = user.get("email", "")
            return "email", email
        elif method is DeliveryMethod.SMS:
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
    def get_method_string(method: DeliveryMethod) -> str:
        if method is DeliveryMethod.EMAIL:
            return "email"
        elif method is DeliveryMethod.SMS:
            return "sms"
        elif method is DeliveryMethod.WHATSAPP:
            return "whatsapp"
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
            validate_email(email=email, check_deliverability=False)
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

        if method != DeliveryMethod.SMS and method != DeliveryMethod.WHATSAPP:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Invalid delivery method"
            )

    def exchange_access_key(self, access_key: str) -> dict:
        uri = EndpointsV1.exchange_auth_access_key_path
        server_response = self.do_post(uri, {}, None, access_key)
        json = server_response.json()
        return self._generate_auth_info(json, None, False)

    @staticmethod
    def _compose_exchange_body(code: str) -> dict:
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
            f"{self.base_url}{EndpointsV2.public_key_path}/{self.project_id}",
            headers=self._get_default_headers(),
            verify=self.secure,
            timeout=self.timeout_seconds,
        )

        if not response.ok:
            if response.status_code == 429:
                self._raise_rate_limit_exception(response)  # Raise RateLimitException
            raise AuthException(
                response.status_code,
                ERROR_TYPE_SERVER_ERROR,
                f"Error: {response.reason}",
            )

        jwks_data = response.text
        try:
            jwkeys_wrapper = json.loads(jwks_data)
            jwkeys = jwkeys_wrapper["keys"]
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

    def adjust_properties(self, jwt_response: dict, user_jwt: bool):
        # Save permissions, roles and tenants info from Session token or from refresh token on the json top level
        if jwt_response.get(SESSION_TOKEN_NAME, None):
            jwt_response["permissions"] = jwt_response.get(SESSION_TOKEN_NAME).get(
                "permissions", []
            )
            jwt_response["roles"] = jwt_response.get(SESSION_TOKEN_NAME).get(
                "roles", []
            )
            jwt_response["tenants"] = jwt_response.get(SESSION_TOKEN_NAME).get(
                "tenants", {}
            )
        elif jwt_response.get(REFRESH_SESSION_TOKEN_NAME, None):
            jwt_response["permissions"] = jwt_response.get(
                REFRESH_SESSION_TOKEN_NAME
            ).get("permissions", [])
            jwt_response["roles"] = jwt_response.get(REFRESH_SESSION_TOKEN_NAME).get(
                "roles", []
            )
            jwt_response["tenants"] = jwt_response.get(REFRESH_SESSION_TOKEN_NAME).get(
                "tenants", {}
            )

        # Save the projectID also in the dict top level
        issuer = jwt_response.get(SESSION_TOKEN_NAME, {}).get(
            "iss", None
        ) or jwt_response.get(REFRESH_SESSION_TOKEN_NAME, {}).get("iss", "")
        jwt_response["projectId"] = issuer.rsplit("/")[
            -1
        ]  # support both url issuer and project ID issuer

        if user_jwt:
            # Save the userID also in the dict top level
            jwt_response["userId"] = jwt_response.get(SESSION_TOKEN_NAME, {}).get(
                "sub", None
            ) or jwt_response.get(REFRESH_SESSION_TOKEN_NAME, {}).get("sub", None)
        else:
            # Save the AccessKeyID also in the dict top level
            jwt_response["keyId"] = jwt_response.get(SESSION_TOKEN_NAME, {}).get(
                "sub", None
            )

        return jwt_response

    def _generate_auth_info(
        self, response_body: dict, refresh_token: str, user_jwt: bool
    ) -> dict:
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

        jwt_response = self.adjust_properties(jwt_response, user_jwt)

        if user_jwt:
            jwt_response[COOKIE_DATA_NAME] = {
                "exp": response_body.get("cookieExpiration", 0),
                "maxAge": response_body.get("cookieMaxAge", 0),
                "domain": response_body.get("cookieDomain", ""),
                "path": response_body.get("cookiePath", "/"),
            }

        return jwt_response

    def generate_jwt_response(self, response_body: dict, refresh_cookie: str) -> dict:
        jwt_response = self._generate_auth_info(response_body, refresh_cookie, True)

        jwt_response["user"] = response_body.get("user", {})
        jwt_response["firstSeen"] = response_body.get("firstSeen", True)
        return jwt_response

    def _get_default_headers(self, pswd: str = None):
        headers = {}
        headers["Content-Type"] = "application/json"

        headers["x-descope-sdk-name"] = "python"

        try:
            headers["x-descope-sdk-python-version"] = platform.python_version()
            headers["x-descope-sdk-version"] = pkg_resources.get_distribution(
                "descope"
            ).version
        except Exception:
            pass

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

    def validate_session(self, session_token: str) -> dict:
        if not session_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Session token is required for validation",
            )

        try:
            res = self._validate_token(session_token)
            return self.adjust_properties(res, True)
        except RateLimitException as e:
            raise e
        except Exception as e:
            raise AuthException(
                401, ERROR_TYPE_INVALID_TOKEN, f"Invalid session token: {e}"
            )

    def refresh_session(self, refresh_token: str) -> dict:
        if not refresh_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Refresh token is required to refresh a session",
            )

        try:
            self._validate_token(refresh_token)
        except RateLimitException as e:
            raise e
        except Exception as e:
            # Refresh is invalid
            raise AuthException(
                401, ERROR_TYPE_INVALID_TOKEN, f"Invalid refresh token: {e}"
            )

        uri = EndpointsV1.refresh_token_path
        response = self.do_post(uri, {}, None, refresh_token)

        resp = response.json()
        return self.generate_jwt_response(resp, refresh_token)

    def validate_and_refresh_session(
        self, session_token: str = None, refresh_token: str = None
    ) -> dict:
        if not session_token and not refresh_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Session and refresh tokens are both empty",
            )

        try:
            return self.validate_session(session_token)
        except Exception:
            # Session is invalid - try to refresh it
            return self.refresh_session(refresh_token)

    @staticmethod
    def extract_masked_address(response: dict, method: DeliveryMethod) -> str:
        if method == DeliveryMethod.SMS or method == DeliveryMethod.WHATSAPP:
            return response["maskedPhone"]
        elif method == DeliveryMethod.EMAIL:
            return response["maskedEmail"]
        return ""
