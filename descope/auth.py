from __future__ import annotations

import copy
import json
import os
import platform
import re
from http import HTTPStatus
import ssl
from threading import Lock
import certifi
from typing import Awaitable, Iterable, Union

import jwt

from descope.future_utils import futu_apply, futu_awaitable

try:
    from importlib.metadata import version
except ImportError:
    from pkg_resources import get_distribution

import httpx
from email_validator import EmailNotValidError, validate_email
from jwt import ExpiredSignatureError, ImmatureSignatureError


from descope.common import (
    COOKIE_DATA_NAME,
    DEFAULT_BASE_URL,
    DEFAULT_DOMAIN,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_URL_PREFIX,
    PHONE_REGEX,
    REFRESH_SESSION_COOKIE_NAME,
    REFRESH_SESSION_TOKEN_NAME,
    SESSION_TOKEN_NAME,
    AccessKeyLoginOptions,
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
        auth_management_key: str | None = None,
        async_mode: bool = False,
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
        self.async_mode = async_mode

        self.base_url = os.getenv("DESCOPE_BASE_URI")
        if not self.base_url:
            self.base_url = self.base_url_for_project_id(self.project_id)
        self.timeout_seconds = timeout_seconds
        self.management_key = management_key or os.getenv("DESCOPE_MANAGEMENT_KEY")
        self.auth_management_key = auth_management_key or os.getenv(
            "DESCOPE_AUTH_MANAGEMENT_KEY"
        )

        public_key = public_key or os.getenv("DESCOPE_PUBLIC_KEY")
        with self.lock_public_keys:
            if not public_key:
                self.public_keys = {}
            else:
                kid, pub_key, alg = self._validate_and_load_public_key(public_key)
                self.public_keys = {kid: (pub_key, alg)}

        if skip_verify:
            self.http_client_kwargs = {"verify": False, "timeout": timeout_seconds}
        else:
            # Backwards compatibility with requests
            ssl_ctx = ssl.create_default_context(
                cafile=os.environ.get("SSL_CERT_FILE", certifi.where()),
                capath=os.environ.get("SSL_CERT_DIR"),
            )
            if os.environ.get("REQUESTS_CA_BUNDLE"):
                ssl_ctx.load_cert_chain(certfile=os.environ.get("REQUESTS_CA_BUNDLE"))

            self.http_client_kwargs = {"verify": ssl_ctx, "timeout": timeout_seconds}

    def _request(
        self, method: str, url: str, **kwargs
    ) -> Union[httpx.Response, Awaitable[httpx.Response]]:
        kwargs = {**kwargs}
        if self.async_mode:
            return self._async_request(method, url, **kwargs)
        else:
            return self._sync_request(method, url, **kwargs)

    def _sync_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        req_kwargs = {**self.http_client_kwargs, **kwargs}
        method_lower = method.lower()
        if method_lower == "get":
            return httpx.get(url, **req_kwargs)
        elif method_lower == "post":
            return httpx.post(url, **req_kwargs)
        elif method_lower == "patch":
            return httpx.patch(url, **req_kwargs)
        elif method_lower == "delete":
            return httpx.delete(url, **req_kwargs)
        elif method_lower == "put":
            return httpx.put(url, **req_kwargs)
        else:
            return httpx.request(method, url, **req_kwargs)

    async def _async_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        async with httpx.AsyncClient(**self.http_client_kwargs) as client:
            method_lower = method.lower()
            if method_lower == "get":
                return await client.get(url, **kwargs)
            elif method_lower == "post":
                return await client.post(url, **kwargs)
            elif method_lower == "patch":
                return await client.patch(url, **kwargs)
            elif method_lower == "delete":
                return await client.delete(url, **kwargs)
            elif method_lower == "put":
                return await client.put(url, **kwargs)
            else:
                return await client.request(method, url, **kwargs)

    def _raise_rate_limit_exception(self, response):
        try:
            resp = response.json()
            raise RateLimitException(
                resp.get("errorCode", HTTPStatus.TOO_MANY_REQUESTS),
                ERROR_TYPE_API_RATE_LIMIT,
                resp.get("errorDescription", ""),
                resp.get("errorMessage", ""),
                rate_limit_parameters={
                    API_RATE_LIMIT_RETRY_AFTER_HEADER: self._parse_retry_after(
                        response.headers
                    )
                },
            )
        except RateLimitException:
            raise
        except Exception:
            raise RateLimitException(
                status_code=HTTPStatus.TOO_MANY_REQUESTS,
                error_type=ERROR_TYPE_API_RATE_LIMIT,
                error_message=ERROR_TYPE_API_RATE_LIMIT,
                error_description=ERROR_TYPE_API_RATE_LIMIT,
            )

    def _parse_retry_after(self, headers):
        try:
            return int(headers.get(API_RATE_LIMIT_RETRY_AFTER_HEADER, 0))
        except (ValueError, TypeError):
            return 0

    def do_get(
        self,
        uri: str,
        params=None,
        follow_redirects=None,
        pswd: str | None = None,
    ) -> Union[httpx.Response, Awaitable[httpx.Response]]:
        """Make GET request, returning Response or awaitable Response based on async_mode."""
        response = self._request(
            "GET",
            f"{self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            params=params,
            follow_redirects=follow_redirects,
        )
        return futu_apply(response, self._raise_from_response_and_return)

    def do_post(
        self,
        uri: str,
        body: dict | list[dict] | list[str] | None,
        params=None,
        pswd: str | None = None,
    ) -> Union[httpx.Response, Awaitable[httpx.Response]]:
        """Make POST request, returning Response or awaitable Response based on async_mode."""
        response = self._request(
            "POST",
            f"{self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            json=body,
            params=params,
            follow_redirects=False,
        )
        return futu_apply(response, self._raise_from_response_and_return)

    def do_patch(
        self,
        uri: str,
        body: dict | list[dict] | list[str] | None,
        params=None,
        pswd: str | None = None,
    ) -> Union[httpx.Response, Awaitable[httpx.Response]]:
        """Make PATCH request, returning Response or awaitable Response based on async_mode."""
        response = self._request(
            "PATCH",
            f"{self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            json=body,
            params=params,
            follow_redirects=False,
        )
        return futu_apply(response, self._raise_from_response_and_return)

    def do_delete(
        self, uri: str, params=None, pswd: str | None = None
    ) -> Union[httpx.Response, Awaitable[httpx.Response]]:
        """Make DELETE request, returning Response or awaitable Response based on async_mode."""
        response = self._request(
            "DELETE",
            f"{self.base_url}{uri}",
            params=params,
            headers=self._get_default_headers(pswd),
            follow_redirects=False,
        )
        return futu_apply(response, self._raise_from_response_and_return)

    def _raise_from_response_and_return(
        self, response: httpx.Response
    ) -> httpx.Response:
        """Helper method to raise exception if needed, then return response."""
        self._raise_from_response(response)
        return response

    def exchange_token(
        self, uri, code: str, audience: str | None | Iterable[str] = None
    ) -> Union[dict, Awaitable[dict]]:
        if not code:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "exchange code is empty",
            )

        body = Auth._compose_exchange_body(code)
        response = self.do_post(uri=uri, body=body, params=None)
        return futu_apply(
            response,
            lambda response: self.generate_jwt_response(
                response.json(),
                response.cookies.get(REFRESH_SESSION_COOKIE_NAME),
                audience,
            ),
        )

    @staticmethod
    def base_url_for_project_id(project_id):
        if len(project_id) >= 32:
            region = project_id[1:5]
            return ".".join([DEFAULT_URL_PREFIX, region, DEFAULT_DOMAIN])
        return DEFAULT_BASE_URL

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
        elif method == DeliveryMethod.VOICE:
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
            DeliveryMethod.VOICE: "voice",
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
            DeliveryMethod.VOICE: ("voice", user.get("phone", "")),
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
            DeliveryMethod.VOICE: "voice",
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

        if (
            method != DeliveryMethod.SMS
            and method != DeliveryMethod.VOICE
            and method != DeliveryMethod.WHATSAPP
        ):
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Invalid delivery method"
            )

    def exchange_access_key(
        self,
        access_key: str,
        audience: str | Iterable[str] | None = None,
        login_options: AccessKeyLoginOptions | None = None,
    ) -> Union[dict, Awaitable[dict]]:
        uri = EndpointsV1.exchange_auth_access_key_path
        body = {
            "loginOptions": login_options.__dict__ if login_options else {},
        }
        server_response = self.do_post(uri=uri, body=body, params=None, pswd=access_key)
        return futu_apply(
            server_response,
            lambda response: self._generate_auth_info(
                response_body=response.json(),
                refresh_token=None,
                user_jwt=False,
                audience=audience,
            ),
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

    def _raise_from_response(self, response: httpx.Response):
        """Raise appropriate exception from response, does nothing if response.is_success is True."""
        if response.is_success:
            return

        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            self._raise_rate_limit_exception(response)  # Raise RateLimitException

        raise AuthException(
            response.status_code,
            ERROR_TYPE_SERVER_ERROR,
            response.text,
        )

    def _fetch_public_keys_sync(self) -> None:
        # This function called under mutex protection so no need to acquire it once again
        response = self._sync_request(
            "GET",
            f"{self.base_url}{EndpointsV2.public_key_path}/{self.project_id}",
            headers=self._get_default_headers(),
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
            jwt_response.get(SESSION_TOKEN_NAME, {}).get("dsub", None)
            or jwt_response.get(SESSION_TOKEN_NAME, {}).get("sub", None)
            or jwt_response.get(REFRESH_SESSION_TOKEN_NAME, {}).get("dsub", None)
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
            jwt_response[SESSION_TOKEN_NAME] = self._validate_token_sync(
                st_jwt, audience
            )
        rt_jwt = response_body.get("refreshJwt", "")
        if rt_jwt:
            jwt_response[REFRESH_SESSION_TOKEN_NAME] = self._validate_token_sync(
                rt_jwt, audience
            )
        elif refresh_token:
            jwt_response[REFRESH_SESSION_TOKEN_NAME] = self._validate_token_sync(
                refresh_token, audience
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
        refresh_cookie: str | None,
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
        headers["x-descope-project-id"] = self.project_id
        bearer = self.project_id
        if pswd:
            bearer = f"{self.project_id}:{pswd}"
        if self.auth_management_key:
            bearer = f"{bearer}:{self.auth_management_key}"
        headers["Authorization"] = f"Bearer {bearer}"
        return headers

    # Validate a token and load the public key if needed.
    def _validate_token_sync(
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
                self._fetch_public_keys_sync()

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
        except ImmatureSignatureError:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Received Invalid token (nbf in future) during jwt validation. Error can be due to time glitch (between machines), try to set the jwt_validation_leeway parameter (in DescopeClient) to higher value than 5sec which is the default",
            )
        except ExpiredSignatureError:
            raise AuthException(
                401,
                ERROR_TYPE_INVALID_TOKEN,
                "Received expired token (exp in past) during jwt validation. (sometimes can be due to time glitch (between machines), try to set the jwt_validation_leeway parameter (in DescopeClient) to higher value than 5sec which is the default)",
            )

        claims["jwt"] = token
        return claims

    def validate_session(
        self, session_token: str, audience: str | None | Iterable[str] = None
    ) -> Union[dict, Awaitable[dict]]:
        """Validate a session token, returning dict or awaitable dict based on async_mode."""
        if not session_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Session token is required for validation",
            )

        res = self._validate_token_sync(session_token, audience)
        res[SESSION_TOKEN_NAME] = copy.deepcopy(
            res
        )  # Duplicate for saving backward compatibility but keep the same structure as the refresh operation response
        return futu_awaitable(self.adjust_properties(res, True), self.async_mode)

    def refresh_session(
        self, refresh_token: str, audience: str | None | Iterable[str] = None
    ) -> Union[dict, Awaitable[dict]]:
        """Refresh a session token, returning dict or awaitable dict based on async_mode."""
        if not refresh_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Refresh token is required to refresh a session",
            )

        self._validate_token_sync(refresh_token, audience)

        response = self.do_post(
            uri=EndpointsV1.refresh_token_path, body={}, params=None, pswd=refresh_token
        )

        def process_response(resp_obj):
            resp = resp_obj.json()
            refresh_token_from_cookie = (
                resp_obj.cookies.get(REFRESH_SESSION_COOKIE_NAME, None) or refresh_token
            )
            return self.generate_jwt_response(resp, refresh_token_from_cookie, audience)

        return futu_apply(response, process_response)

    def validate_and_refresh_session(
        self,
        session_token: str,
        refresh_token: str,
        audience: str | None | Iterable[str] = None,
    ) -> Union[dict, Awaitable[dict]]:
        """Validate session, refresh if needed, returning dict or awaitable dict based on async_mode."""
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

    def select_tenant(
        self,
        tenant_id: str,
        refresh_token: str,
        audience: str | None | Iterable[str] = None,
    ) -> Union[dict, Awaitable[dict]]:
        """Select a tenant, returning dict or awaitable dict based on async_mode."""
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

        def process_response(resp_obj):
            resp = resp_obj.json()
            return self.generate_jwt_response(
                resp, resp_obj.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience
            )

        return futu_apply(response, process_response)

    @staticmethod
    def extract_masked_address(response: dict, method: DeliveryMethod) -> str:
        if (
            method == DeliveryMethod.SMS
            or method == DeliveryMethod.VOICE
            or method == DeliveryMethod.WHATSAPP
        ):
            return response["maskedPhone"]
        elif method == DeliveryMethod.EMAIL:
            return response["maskedEmail"]
        return ""
