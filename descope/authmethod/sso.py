from __future__ import annotations

from typing import Optional

from descope._authmethod_base import AuthMethodBase
from descope.authmethod._sso_base import SSOBase
from descope.common import (
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)


class SSO(SSOBase, AuthMethodBase):
    def start(
        self,
        tenant: str,
        return_url: Optional[str] = None,
        login_options: Optional[LoginOptions] = None,
        refresh_token: Optional[str] = None,
        prompt: Optional[str] = None,
        sso_id: Optional[str] = None,
        login_hint: Optional[str] = None,
        force_authn: Optional[bool] = None,
    ) -> dict:
        """
        Start tenant sso session (saml/oidc based on tenant settings)

        Args:
            tenant (str): The tenant ID or name
            return_url (str, optional): URL to redirect to after authentication
            login_options (LoginOptions, optional): Login options for the authentication
            refresh_token (str, optional): Refresh token for stepup/MFA authentication
            prompt (str, optional): Prompt parameter for the authentication
            sso_id (str, optional): SSO configuration ID to use
            login_hint (str, optional): Hint about the user's login identifier
            force_authn (bool, optional): Force re-authentication even if user is already authenticated

        Return value (dict): the redirect url for the login page
        Return dict in the format
             {'url': 'http://dummy.com/login..'}
        """
        self._validate_tenant(tenant)

        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.auth_sso_start_path
        params = self._compose_start_params(
            tenant,
            return_url if return_url else "",
            prompt if prompt else "",
            sso_id if sso_id else "",
            login_hint if login_hint else "",
            force_authn,
        )
        response = self._http.post(
            uri,
            body=login_options.__dict__ if login_options else {},
            params=params,
            pswd=refresh_token,
        )

        return response.json()

    def exchange_token(self, code: str) -> dict:
        return self._auth.exchange_token(EndpointsV1.sso_exchange_token_path, code)
