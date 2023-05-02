from descope._auth_base import AuthBase
from descope.common import EndpointsV1, LoginOptions, validate_refresh_token_provided
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class SAML(AuthBase):
    def start(
        self,
        tenant: str,
        return_url: str = None,
        login_options: LoginOptions = None,
        refresh_token: str = None,
    ) -> dict:
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

        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.auth_saml_start_path
        params = SAML._compose_start_params(tenant, return_url)
        response = self._auth.do_post(
            uri, login_options.__dict__ if login_options else {}, params, refresh_token
        )

        return response.json()

    def exchange_token(self, code: str) -> dict:
        uri = EndpointsV1.saml_exchange_token_path
        return self._auth.exchange_token(uri, code)

    @staticmethod
    def _compose_start_params(tenant: str, return_url: str) -> dict:
        res = {"tenant": tenant}
        if return_url is not None and return_url != "":
            res["redirectURL"] = return_url
        return res
