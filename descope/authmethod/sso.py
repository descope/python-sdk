from typing import Any, Optional

from descope._auth_base import AuthBase
from descope.common import EndpointsV1, LoginOptions, validate_refresh_token_provided
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class SSO(AuthBase):
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
        if not tenant:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Tenant cannot be empty"
            )

        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.auth_sso_start_path
        params = SSO._compose_start_params(
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
        uri = EndpointsV1.sso_exchange_token_path
        return self._auth.exchange_token(uri, code)

    @staticmethod
    def _compose_start_params(
        tenant: str,
        return_url: str,
        prompt: str,
        sso_id: str,
        login_hint: str,
        force_authn: Optional[bool],
    ) -> dict:
        res: dict[str, Any] = {"tenant": tenant}
        if return_url is not None and return_url != "":
            res["redirectURL"] = return_url
        if prompt is not None and prompt != "":
            res["prompt"] = prompt
        if sso_id is not None and sso_id != "":
            res["ssoId"] = sso_id
        if login_hint is not None and login_hint != "":
            res["loginHint"] = login_hint
        if force_authn is not None:
            res["forceAuthn"] = force_authn
        return res
