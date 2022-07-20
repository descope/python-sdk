
from descope.authhelper import AuthHelper
from descope.exceptions import AuthException
from descope.common import EndpointsV1, OAuthProviders


class OAuth():
    _auth_helper:AuthHelper = None
    
    def __init__(self, auth_helper: AuthHelper):
        self._auth_helper = auth_helper
        
    def start(self, provider: str) -> str:
        """ """
        if not self._verify_provider(provider):
            raise AuthException(
                500,
                "Unknown OAuth provider",
                f"Unknown OAuth provider: {provider}",
            )

        uri = EndpointsV1.oauthStart
        response = self._auth_helper.do_get(uri, None, {"provider": provider}, False)
    
        if not response.ok:
            raise AuthException(
                response.status_code, "OAuth send request failure", response.text
            )

        redirect_url = response.headers.get("Location", "")
        return redirect_url

    @staticmethod
    def _verify_provider(oauth_provider: str) -> str:
        if oauth_provider == "" or oauth_provider is None:
            return False

        if oauth_provider in OAuthProviders:
            return True
        else:
            return False