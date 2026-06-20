from __future__ import annotations

import copy
import json
from threading import Lock
from typing import Iterable, Optional

from descope._auth_base import AuthBase
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_TOKEN_NAME,
    AccessKeyLoginOptions,
    EndpointsV1,
    EndpointsV2,
)
from descope.exceptions import (
    ERROR_TYPE_INVALID_ARGUMENT,
    ERROR_TYPE_INVALID_PUBLIC_KEY,
    ERROR_TYPE_INVALID_TOKEN,
    AuthException,
)
from descope.http_client import HTTPClient


class Auth(AuthBase):
    def __init__(
        self,
        project_id: Optional[str] = None,
        public_key: Optional[dict | str] = None,
        jwt_validation_leeway: int = 5,
        *,
        http_client: HTTPClient,
    ):
        self.lock_public_keys = Lock()
        super().__init__(project_id, public_key, jwt_validation_leeway)
        self._http = http_client

    @property
    def http_client(self) -> HTTPClient:
        return self._http

    def exchange_token(self, uri, code: str, audience: Optional[Iterable[str] | str] = None) -> dict:
        if not code:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "exchange code is empty",
            )

        body = Auth._compose_exchange_body(code)
        response = self._http.post(uri, body=body)
        resp = response.json()
        jwt_response = self.generate_jwt_response(resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME), audience)
        return jwt_response

    def exchange_access_key(
        self,
        access_key: str,
        audience: str | Iterable[str] | None = None,
        login_options: AccessKeyLoginOptions | None = None,
    ) -> dict:
        uri = EndpointsV1.exchange_auth_access_key_path
        body = {
            "loginOptions": (
                {k: v for k, v in login_options.__dict__.items() if v is not None} if login_options else {}
            ),
        }
        server_response = self._http.post(uri, body=body, pswd=access_key)
        json_body = server_response.json()
        return self._generate_auth_info(
            response_body=json_body,
            refresh_token=None,
            user_jwt=False,
            audience=audience,
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
            raise AuthException(500, ERROR_TYPE_INVALID_PUBLIC_KEY, f"Unable to load jwks. Error: {e}")

        # Load all public keys for this project
        self.public_keys = {}
        for key in jwkeys:
            try:
                loaded_kid, pub_key, alg = Auth._validate_and_load_public_key(key)
                self.public_keys[loaded_kid] = (pub_key, alg)
            except AuthException:
                # just continue to the next key
                pass

    # public method to validate a token from the management class
    def validate_token(self, token: str, audience: str | None | Iterable[str] = None) -> dict:
        return self._validate_token(token, audience)

    # Validate a token and load the public key if needed
    def _validate_token(self, token: str, audience: str | None | Iterable[str] = None) -> dict:
        kid, alg_header = self._kid_alg_from_token(token)

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

        return self._decode_and_verify_token(token, audience, copy_key, alg_header)

    def validate_session(self, session_token: str, audience: str | None | Iterable[str] = None) -> dict:
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

    def refresh_session(self, refresh_token: str, audience: str | None | Iterable[str] = None) -> dict:
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
        refresh_token = response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None) or refresh_token
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
