from __future__ import annotations

from typing import Optional

from descope._auth_base import AuthBase
from descope.authmethod._saml_base import SAMLBase
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)


# This class is DEPRECATED please use SSO instead
class SAML(SAMLBase, AuthBase):
    def start(
        self,
        tenant: str,
        return_url: Optional[str] = None,
        login_options: Optional[LoginOptions] = None,
        refresh_token: Optional[str] = None,
    ) -> dict:
        """
        DEPRECATED
        """
        self._validate_tenant(tenant)
        self._validate_return_url(return_url)

        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.auth_saml_start_path
        params = self._compose_start_params(tenant, return_url)
        response = self._http.post(
            uri,
            body=login_options.__dict__ if login_options else {},
            params=params,
            pswd=refresh_token,
        )

        return response.json()

    def exchange_token(self, code: str) -> dict:
        self._validate_exchange_code(code)
        uri = EndpointsV1.saml_exchange_token_path
        body = self._compose_exchange_body(code)
        response = self._http.post(uri, body=body)
        return self._auth.generate_jwt_response(
            response.json(), response.cookies.get(REFRESH_SESSION_COOKIE_NAME), None
        )
