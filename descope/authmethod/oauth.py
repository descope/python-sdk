from descope.authhelper import AuthHelper
from descope.exceptions import AuthException
from descope.common import EndpointsV1, OAuthProviders
from descope.authmethod.exchanger import Exchanger  # noqa: F401


class OAuth(Exchanger):
    def __init__(self, auth_helper: AuthHelper):
        super().__init__(auth_helper)
        
    def start(self, provider: str, return_url: str = "") -> dict:
        """ """
        if not self._verify_provider(provider):
            raise AuthException(
                500,
                "Unknown OAuth provider",
                f"Unknown OAuth provider: {provider}",
            )

        uri = EndpointsV1.oauthStart
        params = OAuth._compose_start_params(provider, return_url)
        response = self._auth_helper.do_get(uri, None, params, False)
    
        return response.json()

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
        if returnURL is not None and returnURL != "":
            res["redirectURL"] = returnURL
        return res