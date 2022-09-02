from descope.auth import Auth
from descope.common import EndpointsV1, OAuthProviders
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class OAuth:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def start(self, provider: str, return_url: str = "") -> dict:
        """ """
        if not self._verify_provider(provider):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Unknown OAuth provider: {provider}",
            )

        uri = EndpointsV1.oauthStart
        params = OAuth._compose_start_params(provider, return_url)
        response = self._auth.do_get(uri, params, False)

        return response.json()

    def exchange_token(self, code: str) -> dict:
        uri = EndpointsV1.oauthExchangeTokenPath
        return self._auth.exchange_token(uri, code)

    @staticmethod
    def _verify_provider(oauth_provider: str) -> str:
        if oauth_provider == "" or oauth_provider is None:
            return False

        if oauth_provider in OAuthProviders:
            return True
        else:
            return False

    @staticmethod
    def _compose_start_params(provider: str, returnURL: str) -> dict:
        res = {"provider": provider}
        if returnURL:
            res["redirectURL"] = returnURL
        return res
