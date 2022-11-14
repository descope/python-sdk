from descope.auth import Auth
from descope.common import EndpointsV1, LoginOptions, validateRefreshTokenProvided
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class OAuth:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def start(
        self,
        provider: str,
        return_url: str = "",
        loginOptions: LoginOptions = None,
        refreshToken: str = None,
    ) -> dict:
        """ """
        if not self._verify_provider(provider):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Unknown OAuth provider: {provider}",
            )

        validateRefreshTokenProvided(loginOptions, refreshToken)

        uri = EndpointsV1.oauthStart
        params = OAuth._compose_start_params(provider, return_url)
        response = self._auth.do_post(
            uri, loginOptions.__dict__ if loginOptions else {}, params, refreshToken
        )

        return response.json()

    def exchange_token(self, code: str) -> dict:
        uri = EndpointsV1.oauthExchangeTokenPath
        return self._auth.exchange_token(uri, code)

    @staticmethod
    def _verify_provider(oauth_provider: str) -> str:
        if oauth_provider == "" or oauth_provider is None:
            return False
        return True

    @staticmethod
    def _compose_start_params(provider: str, returnURL: str) -> dict:
        res = {"provider": provider}
        if returnURL:
            res["redirectURL"] = returnURL
        return res
