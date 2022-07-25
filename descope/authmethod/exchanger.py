from descope.auth import Auth
from descope.common import REFRESH_SESSION_COOKIE_NAME, EndpointsV1
from descope.exceptions import AuthException


class Exchanger:
    _auth: Auth = None

    def __init__(self, auth: Auth):
        self._auth = auth

    def exchange_token(self, code: str) -> dict:
        """ """
        if not code or code == "":
            raise AuthException(
                400,
                "Empty exchange code",
                "Empty exchange code",
            )

        uri = EndpointsV1.exchangeTokenPath
        params = Exchanger._compose_exchange_params(code)
        response = self._auth.do_get(uri, None, params, False)
        resp = response.json()
        jwt_response = self._auth._generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    @staticmethod
    def _compose_exchange_params(code: str) -> dict:
        return {"code": code}
