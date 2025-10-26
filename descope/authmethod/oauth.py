from typing import Optional

from descope._auth_base import AuthBase
from descope.common import EndpointsV1, LoginOptions, validate_refresh_token_provided
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class OAuth(AuthBase):
    def start(
        self,
        provider: str,
        return_url: str = "",
        login_options: Optional[LoginOptions] = None,
        refresh_token: Optional[str] = None,
    ) -> dict:
        """ """
        if not self._verify_provider(provider):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Unknown OAuth provider: {provider}",
            )

        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.oauth_start_path
        params = OAuth._compose_start_params(provider, return_url)
        response = self._http.post(
            uri,
            body=login_options.__dict__ if login_options else {},
            params=params,
            pswd=refresh_token,
        )

        return response.json()

    def exchange_token(self, code: str) -> dict:
        uri = EndpointsV1.oauth_exchange_token_path
        return self._auth.exchange_token(uri, code)

    @staticmethod
    def _verify_provider(oauth_provider: str) -> bool:
        if oauth_provider == "" or oauth_provider is None:
            return False
        return True

    @staticmethod
    def _compose_start_params(provider: str, return_url: str) -> dict:
        res = {"provider": provider}
        if return_url:
            res["redirectURL"] = return_url
        return res
