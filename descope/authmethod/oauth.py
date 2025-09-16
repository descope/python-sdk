from typing import Awaitable, Optional, Union

from descope._auth_base import AuthBase
from descope.common import (
    EndpointsV1,
    LoginOptions,
    REFRESH_SESSION_COOKIE_NAME,
    validate_refresh_token_provided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.future_utils import futu_apply


class OAuth(AuthBase):
    def start(
        self,
        provider: str,
        return_url: str = "",
        login_options: Optional[LoginOptions] = None,
        refresh_token: Optional[str] = None,
    ) -> Union[dict, Awaitable[dict]]:
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
        response = self._auth.do_post(
            uri, login_options.__dict__ if login_options else {}, params, refresh_token
        )

        return futu_apply(
            response,
            lambda response: response.json(),
        )

    def exchange_token(self, code: str) -> Union[dict, Awaitable[dict]]:
        if not code:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "exchange code is empty",
            )

        uri = EndpointsV1.oauth_exchange_token_path
        response = self._auth.do_post(uri, {"code": code}, None)
        return futu_apply(
            response,
            lambda response: self._auth.generate_jwt_response(
                response.json(),
                response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None),
                None,
            ),
        )

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
