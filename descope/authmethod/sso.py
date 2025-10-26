from typing import Optional

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
    ) -> dict:
        """
        Start tenant sso session (saml/oidc based on tenant settings)

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
        tenant: str, return_url: str, prompt: str, sso_id: str
    ) -> dict:
        res = {"tenant": tenant}
        if return_url is not None and return_url != "":
            res["redirectURL"] = return_url
        if prompt is not None and prompt != "":
            res["prompt"] = prompt
        if sso_id is not None and sso_id != "":
            res["ssoId"] = sso_id
        return res
