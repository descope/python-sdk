
from descope.authhelper import AuthHelper
from descope.exceptions import AuthException
from descope.common import EndpointsV1, REFRESH_SESSION_COOKIE_NAME


class Exchanger(object):
    _auth_helper:AuthHelper = None
    
    def __init__(self, auth_helper: AuthHelper):
        self._auth_helper = auth_helper
        
    def exchange_token(self, code: str) -> str:
        """ """
        if not code or code == "":
            raise AuthException(
                400,
                "Empty exchange code",
                "Empty exchange code",
            )

        uri = EndpointsV1.exchangeTokenPath
        params = Exchanger._compose_exchange_params(code)
        response = self._auth_helper.do_get(uri, None, params, False)
        resp = response.json()
        jwt_response = self._auth_helper._generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response
        
    @staticmethod
    def _compose_exchange_params(code: str) -> dict:
        return {"code": code}