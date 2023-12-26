from __future__ import annotations

import copy
import json
import os
import platform
import re
from collections.abc import Iterable
from http import HTTPStatus
from threading import Lock

import jwt

try:
    from importlib.metadata import version
except ImportError:
    from pkg_resources import get_distribution

import requests
from email_validator import EmailNotValidError, validate_email
from jwt import ExpiredSignatureError, ImmatureSignatureError

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


def sdk_version():
    try:
        return version("descope")
    except NameError:
        return get_distribution("descope").version


_default_headers = {
    "Content-Type": "application/json",
    "x-descope-sdk-name": "python",
    "x-descope-sdk-python-version": platform.python_version(),
    "x-descope-sdk-version": sdk_version(),
}


class Auth:
    ALGORITHM_KEY = "alg"

    def __init__(
        self,
        project_id: str | None = None,
        public_key: dict | str | None = None,
        skip_verify: bool = False,
        management_key: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        jwt_validation_leeway: int = 5,
    ):
        self.lock_public_keys = Lock()
        # validate project id
        project_id = project_id or os.getenv("DESCOPE_PROJECT_ID", "")
        if not project_id:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                (
                    "Unable to init Auth object because project_id cannot be empty. "
                    "Set environment variable DESCOPE_PROJECT_ID or pass your Project ID to the init function."
                ),
            )
        self.project_id = project_id
        self.jwt_validation_leeway = jwt_validation_leeway
        self.secure = not skip_verify

        self.base_url = os.getenv("DESCOPE_BASE_URI") or DEFAULT_BASE_URL
        self.timeout_seconds = timeout_seconds
        self.management_key = management_key or os.getenv("DESCOPE_MANAGEMENT_KEY")

        public_key = public_key or os.getenv("DESCOPE_PUBLIC_KEY")
        with self.lock_public_keys:
            if not public_key:
                self.public_keys = {}
            else:
                kid, pub_key, alg = self._validate_and_load_public_key(public_key)
                self.public_keys = {kid: (pub_key, alg)}

    def _raise_rate_limit_exception(self, response):
        resp = response.json()
        raise RateLimitException(
            resp.get("errorCode", HTTPStatus.TOO_MANY_REQUESTS),
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
        pswd: str | None = None,
    ) -> requests.Response:
        response = requests.get(
            f"{self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            params=params,
            allow_redirects=allow_redirects,
            verify=self.secure,
            timeout=self.timeout_seconds,
        )
        self._raise_from_response(response)
        return response

    def do_post(
        self, uri: str, body: dict | None, params=None, pswd: str | None = None
    ) -> requests.Response:
        response = requests.post(
            f"{self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            json=body,
            allow_redirects=False,
            verify=self.secure,
            params=params,
            timeout=self.timeout_seconds,
        )
        self._raise_from_response(response)
        return response

    def do_delete(
        self, uri: str, params=None, pswd: str | None = None
    ) -> requests.Response:
        response = requests.delete(
            f"{self.base_url}{uri}",
            params=params,
            headers=self._get_default_headers(pswd),
            allow_redirects=False,
            verify=self.secure,
            timeout=self.timeout_seconds,
        )
        self._raise_from_response(response)
        return response

    def exchange_token(self, uri, code: str) -> dict:
        if not code:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "exchange code is empty",
            )

        body = Auth._compose_exchange_body(code)
        response = self.do_post(uri=uri, body=body, params=None)
        resp = response.json()
        jwt_response = self.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME), None
        )
        return jwt_response

    @staticmethod
    def adjust_and_verify_delivery_method(
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
                validate_email(user["email"], check_deliverability=False)
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
        suffix = {
            DeliveryMethod.EMAIL: "email",
            DeliveryMethod.SMS: "sms",
            DeliveryMethod.WHATSAPP: "whatsapp",
        }.get(method)

        if not suffix:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, f"Unknown delivery method: {method}"
            )

        return f"{base}/{suffix}"

    @staticmethod
    def get_login_id_by_method(method: DeliveryMethod, user: dict) -> tuple[str, str]:
        login_id = {
            DeliveryMethod.EMAIL: ("email", user.get("email", "")),
            DeliveryMethod.SMS: ("phone", user.get("phone", "")),
            DeliveryMethod.WHATSAPP: ("whatsapp", user.get("phone", "")),
        }.get(method)

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, f"Unknown delivery method: {method}"
            )

        return login_id

    @staticmethod
    def get_method_string(method: DeliveryMethod) -> str:
        name = {
            DeliveryMethod.EMAIL: "email",
            DeliveryMethod.SMS: "sms",
            DeliveryMethod.WHATSAPP: "whatsapp",
            DeliveryMethod.EMBEDDED: "Embedded",
        }.get(method)

        if not name:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, f"Unknown delivery method: {method}"
            )

        return name

    @staticmethod
    def validate_email(email: str):
        if email == "":
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "email address argument cannot be empty",
            )

        try:
            validate_email(email, check_deliverability=False)
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

    def exchange_access_key(
        self, access_key: str, audience: str | Iterable[str] | None = None
    ) -> dict:
        uri = EndpointsV1.exchange_auth_access_key_path
        server_response = self.do_post(uri=uri, body={}, params=None, pswd=access_key)
        json = server_response.json()
        return self._generate_auth_info(
            response_body=json, refresh_token=None, user_jwt=False, audience=audience
        )

    @staticmethod
    def _compose_exchange_body(code: str) -> dict:
        return {"code": code}

    @staticmethod
    def _validate_and_load_public_key(public_key) -> tuple[str, jwt.PyJWK, str]:
        if not isinstance(public_key, (str, dict)):
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                "Unable to load public key. Invalid public key error: (unknown type)",
            )

        if isinstance(public_key, str):
            try:
                public_key = json.loads(public_key)
            except (ValueError, TypeError) as e:
                raise AuthException(
                    500,
                    ERROR_TYPE_INVALID_PUBLIC_KEY,
                    f"Unable to load public key. error: {e}",
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
        except (jwt.PyJWKError, jwt.InvalidKeyError) as e:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                f"Unable to load public key {e}",
            )

    def _raise_from_response(self, response):
        """Raise appropriate exception from response, does nothing if response.ok is True."""
        if response.ok:
            return

        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            self._raise_rate_limit_exception(response)  # Raise RateLimitException

        raise AuthException(
            response.status_code,
            ERROR_TYPE_SERVER_ERROR,
            response.text,
        )

    def _fetch_public_keys(self) -> None:
        # This function called under mutex protection so no need to acquire it once again
        response = requests.get(
            f"{self.base_url}{EndpointsV2.public_key_path}/{self.project_id}",
            headers=self._get_default_headers(),
            verify=self.secure,
            timeout=self.timeout_seconds,
        )
        self._raise_from_response(response)

        jwks_data = response.text
        try:
            jwkeys_wrapper = json.loads(jwks_data)
            jwkeys = jwkeys_wrapper["keys"]
        except (ValueError, TypeError, KeyError) as e:
            raise AuthException(
                500, ERROR_TYPE_INVALID_PUBLIC_KEY, f"Unable to load jwks. Error: {e}"
            )

        # Load all public keys for this project
        self.public_keys = {}
        for key in jwkeys:
            try:
                loaded_kid, pub_key, alg = Auth._validate_and_load_public_key(key)
                self.public_keys[loaded_kid] = (pub_key, alg)
            except AuthException:
                # just continue to the next key
                pass

    def adjust_properties(self, jwt_response: dict, user_jwt: bool):
        # Save permissions, roles and tenants info from Session token or from refresh token on the json top level
        if SESSION_TOKEN_NAME in jwt_response:
            jwt_response["permissions"] = jwt_response[SESSION_TOKEN_NAME].get(
                "permissions", []
            )
            jwt_response["roles"] = jwt_response[SESSION_TOKEN_NAME].get("roles", [])
            jwt_response["tenants"] = jwt_response[SESSION_TOKEN_NAME].get(
                "tenants", {}
            )
        elif REFRESH_SESSION_TOKEN_NAME in jwt_response:
            jwt_response["permissions"] = jwt_response[REFRESH_SESSION_TOKEN_NAME].get(
                "permissions", []
            )
            jwt_response["roles"] = jwt_response[REFRESH_SESSION_TOKEN_NAME].get(
                "roles", []
            )
            jwt_response["tenants"] = jwt_response[REFRESH_SESSION_TOKEN_NAME].get(
                "tenants", {}
            )
        else:
            jwt_response["permissions"] = jwt_response.get("permissions", [])
            jwt_response["roles"] = jwt_response.get("roles", [])
            jwt_response["tenants"] = jwt_response.get("tenants", {})

        # Save the projectID also in the dict top level
        issuer = (
            jwt_response.get(SESSION_TOKEN_NAME, {}).get("iss", None)
            or jwt_response.get(REFRESH_SESSION_TOKEN_NAME, {}).get("iss", None)
            or jwt_response.get("iss", "")
        )
        jwt_response["projectId"] = issuer.rsplit("/")[
            -1
        ]  # support both url issuer and project ID issuer

        sub = (
            jwt_response.get(SESSION_TOKEN_NAME, {}).get("sub", None)
            or jwt_response.get(REFRESH_SESSION_TOKEN_NAME, {}).get("sub", None)
            or jwt_response.get("sub", "")
        )
        if user_jwt:
            # Save the userID also in the dict top level
            jwt_response["userId"] = sub
        else:
            # Save the AccessKeyID also in the dict top level
            jwt_response["keyId"] = sub

        return jwt_response

    def _generate_auth_info(
        self,
        response_body: dict,
        refresh_token: str | None,
        user_jwt: bool,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        jwt_response = {}
        st_jwt = response_body.get("sessionJwt", "")
        if st_jwt:
            jwt_response[SESSION_TOKEN_NAME] = self._validate_token(st_jwt, audience)
        rt_jwt = response_body.get("refreshJwt", "")
        if refresh_token:
            jwt_response[REFRESH_SESSION_TOKEN_NAME] = self._validate_token(
                refresh_token, audience
            )
        elif rt_jwt:
            jwt_response[REFRESH_SESSION_TOKEN_NAME] = self._validate_token(
                rt_jwt, audience
            )

        jwt_response = self.adjust_properties(jwt_response, user_jwt)

        if user_jwt:
            jwt_response[COOKIE_DATA_NAME] = {
                "exp": response_body.get("cookieExpiration", 0),
                "maxAge": response_body.get("cookieMaxAge", 0),
                "domain": response_body.get("cookieDomain", ""),
                "path": response_body.get("cookiePath", "/"),
            }

        return jwt_response

    def generate_jwt_response(
        self,
        response_body: dict,
        refresh_cookie: str,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        jwt_response = self._generate_auth_info(
            response_body, refresh_cookie, True, audience
        )

        jwt_response["user"] = response_body.get("user", {})
        jwt_response["firstSeen"] = response_body.get("firstSeen", True)
        return jwt_response

    def _get_default_headers(self, pswd: str | None = None):
        headers = _default_headers.copy()
        bearer = self.project_id
        if pswd:
            bearer = f"{self.project_id}:{pswd}"
        headers["Authorization"] = f"Bearer {bearer}"
        return headers

    # Validate a token and load the public key if needed
    def _validate_token(
        self, token: str, audience: str | None | Iterable[str] = None
    ) -> dict:
        if not token:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_TOKEN,
                "Token validation received empty token",
            )
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.exceptions.PyJWTError as e:
            raise AuthException(
                500,
                ERROR_TYPE_INVALID_TOKEN,
                f"Unable to parse token header. Error: {e}",
            ) from e

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

        try:
            claims = jwt.decode(
                jwt=token,
                key=copy_key[0].key,
                algorithms=[alg_header],
                audience=audience,
                leeway=self.jwt_validation_leeway,
            )
        except (ImmatureSignatureError, ExpiredSignatureError):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Received Invalid token times error due to time glitch (between machines) during jwt validation, try to set the jwt_validation_leeway parameter (in DescopeClient) to higher value than 5sec which is the default",
            )

        claims["jwt"] = token
        return claims

    def validate_session(
        self, session_token: str, audience: str | None | Iterable[str] = None
    ) -> dict:
        if not session_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Session token is required for validation",
            )

        res = self._validate_token(session_token, audience)
        res[SESSION_TOKEN_NAME] = copy.deepcopy(
            res
        )  # Duplicate for saving backward compatibility but keep the same structure as the refresh operation response
        return self.adjust_properties(res, True)

    def refresh_session(
        self, refresh_token: str, audience: str | None | Iterable[str] = None
    ) -> dict:
        if not refresh_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Refresh token is required to refresh a session",
            )

        self._validate_token(refresh_token, audience)

        uri = EndpointsV1.refresh_token_path
        response = self.do_post(uri=uri, body={}, params=None, pswd=refresh_token)

        resp = response.json()
        return self.generate_jwt_response(resp, refresh_token, audience)

    def validate_and_refresh_session(
        self,
        session_token: str,
        refresh_token: str,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        if not session_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Session token is missing",
            )

        try:
            return self.validate_session(session_token, audience)
        except AuthException:
            # Session is invalid - try to refresh it
            if not refresh_token:
                raise AuthException(
                    400,
                    ERROR_TYPE_INVALID_TOKEN,
                    "Refresh token is missing",
                )
            return self.refresh_session(refresh_token, audience)

    def select_tenant(self, tenant_id: str, refresh_token: str) -> dict:
        if not refresh_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Refresh token is required to refresh a session",
            )

        uri = EndpointsV1.select_tenant_path
        response = self.do_post(
            uri=uri, body={"tenant": tenant_id}, params=None, pswd=refresh_token
        )

        resp = response.json()
        jwt_response = self.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), None
        )
        return jwt_response

    @staticmethod
    def extract_masked_address(response: dict, method: DeliveryMethod) -> str:
        if method == DeliveryMethod.SMS or method == DeliveryMethod.WHATSAPP:
            return response["maskedPhone"]
        elif method == DeliveryMethod.EMAIL:
            return response["maskedEmail"]
        return ""
