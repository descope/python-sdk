from descope.auth import Auth
from descope.common import EndpointsV1, LoginOptions
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class SAML:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def start(self, tenant: str, return_url: str = None) -> dict:
        """
        Docs
        """
        if not tenant:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Tenant cannot be empty"
            )

        if not return_url:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Return url cannot be empty"
            )

        uri = EndpointsV1.authSAMLStart
        params = SAML._compose_start_params(tenant, return_url)
        response = self._auth.do_post(uri, {}, params)

        return response.json()

    def exchange_token(
        self, code: str, loginOptions: LoginOptions = None, refreshToken: str = None
    ) -> dict:
        uri = EndpointsV1.samlExchangeTokenPath
        return self._auth.exchange_token(uri, code, loginOptions, refreshToken)

    @staticmethod
    def _compose_start_params(tenant: str, return_url: str) -> dict:
        res = {"tenant": tenant}
        if return_url is not None and return_url != "":
            res["redirectURL"] = return_url
        return res
