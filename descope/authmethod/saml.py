from descope.authhelper import AuthHelper
from descope.common import EndpointsV1
from descope.exceptions import AuthException
from descope.authmethod.exchanger import Exchanger  # noqa: F401


class SAML(Exchanger):
    def __init__(self, auth_helper: AuthHelper):
        super().__init__(auth_helper)

    def start(self, tenant: str, return_url: str = None) -> dict:
        """
        Docs
        """
        if tenant is None or tenant == "":
            raise AuthException(500, "Invalid argument", "Tenant cannot be empty")

        if return_url is None or return_url == "":
            raise AuthException(500, "Invalid argument", "Return url cannot be empty")

        uri = EndpointsV1.authSAMLStart
        params = SAML._compose_start_params(tenant, return_url)
        response = self._auth_helper.do_get(uri, None, params)

        return response.json()
    
    @staticmethod
    def _compose_start_params(tenant: str, return_url: str) -> dict:
        res = {"tenant": tenant}
        if return_url is not None and return_url != "":
            res["redirectURL"] = return_url
        return res
