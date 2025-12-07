from __future__ import annotations

import copy
import json
import os
import re
from http import HTTPStatus
from threading import Lock
from typing import Iterable, Optional

import jwt
from email_validator import EmailNotValidError, validate_email
from jwt import ExpiredSignatureError, ImmatureSignatureError

from descope.common import (
    DEFAULT_BASE_URL,
    DEFAULT_DOMAIN,
    DEFAULT_URL_PREFIX,
    PHONE_REGEX,
    REFRESH_SESSION_COOKIE_NAME,
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
from descope.http_client import HTTPClient
from descope.jwt_common import adjust_properties as jwt_adjust_properties
from descope.jwt_common import generate_auth_info as jwt_generate_auth_info
from descope.jwt_common import generate_jwt_response as jwt_generate_jwt_response


class Auth:
    ALGORITHM_KEY = "alg"

    def __init__(
        self,
        project_id: Optional[str] = None,
        public_key: Optional[dict | str] = None,
        jwt_validation_leeway: int = 5,
        *,
        http_client: HTTPClient,
    ):
        self.lock_public_keys = Lock()

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

        self._http = http_client

        public_key = public_key or os.getenv("DESCOPE_PUBLIC_KEY")
        with self.lock_public_keys:
            if not public_key:
                self.public_keys = {}
            else:
                kid, pub_key, alg = self._validate_and_load_public_key(public_key)
                self.public_keys = {kid: (pub_key, alg)}

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

    @property
    def http_client(self) -> HTTPClient:
        return self._http

    def exchange_token(
        self, uri, code: str, audience: Optional[Iterable[str] | str] = None
    ) -> dict:
        if not code:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "exchange code is empty",
            )

        body = Auth._compose_exchange_body(code)
        response = self._http.post(uri, body=body)
        resp = response.json()
        jwt_response = self.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME), audience
        )
        return jwt_response

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
    ) -> dict:
        uri = EndpointsV1.exchange_auth_access_key_path
        body = {
            "loginOptions": login_options.__dict__ if login_options else {},
        }
        server_response = self._http.post(uri, body=body, pswd=access_key)
        json_body = server_response.json()
        return self._generate_auth_info(
            response_body=json_body,
            refresh_token=None,
            user_jwt=False,
            audience=audience,
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
        response = self._http.get(
            f"{EndpointsV2.public_key_path}/{self.project_id}",
        )

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
        # Delegate to shared JWT utilities for normalization
        return jwt_adjust_properties(jwt_response, user_jwt)

    def _generate_auth_info(
        self,
        response_body: dict,
        refresh_token: str | None,
        user_jwt: bool,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        # Use shared generator with class validator to preserve signature checks
        return jwt_generate_auth_info(
            response_body,
            refresh_token,
            user_jwt,
            audience,
            token_validator=self._validate_token,
        )

    def generate_jwt_response(
        self,
        response_body: dict,
        refresh_cookie: str | None,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        # Delegate to shared implementation (keeps same output shape)
        return jwt_generate_jwt_response(
            response_body,
            refresh_cookie,
            audience,
            token_validator=self._validate_token,
        )

    # public method to validate a token from the management class
    def validate_token(
        self, token: str, audience: str | None | Iterable[str] = None
    ) -> dict:
        return self._validate_token(token, audience)

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

        # Check if we need to auto-detect audience from token
        validation_audience = audience
        if audience is None:
            try:
                unverified_claims = jwt.decode(
                    jwt=token,
                    key=copy_key[0].key,
                    algorithms=[alg_header],
                    options={"verify_aud": False},  # Skip audience verification for now
                    leeway=self.jwt_validation_leeway,
                )
                token_audience = unverified_claims.get("aud")

                # If token has audience claim and it matches our project ID, use it
                if token_audience and self.project_id:
                    if isinstance(token_audience, list):
                        if self.project_id in token_audience:
                            validation_audience = self.project_id
                    else:
                        if token_audience == self.project_id:
                            validation_audience = self.project_id
            except Exception:
                # If we can't decode the token to check audience, proceed with original audience (None)
                pass

        try:
            claims = jwt.decode(
                jwt=token,
                key=copy_key[0].key,
                algorithms=[alg_header],
                audience=validation_audience,
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
        response = self._http.post(uri, body={}, pswd=refresh_token)

        resp = response.json()
        refresh_token = (
            response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None) or refresh_token
        )
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

    def select_tenant(
        self,
        tenant_id: str,
        refresh_token: str,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        if not refresh_token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                "Refresh token is required to refresh a session",
            )

        uri = EndpointsV1.select_tenant_path
        response = self._http.post(uri, body={"tenant": tenant_id}, pswd=refresh_token)

        resp = response.json()
        jwt_response = self.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience
        )
        return jwt_response

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
