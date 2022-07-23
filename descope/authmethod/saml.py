from descope.authhelper import AuthHelper
from descope.common import EndpointsV1
from descope.exceptions import AuthException


class SAML:
    _auth_helper: AuthHelper

    def __init__(self, auth_helper):
        self._auth_helper = auth_helper

    @staticmethod
    def _compose_start_params(tenantId: str, returnURL: str) -> dict:
        res = {"tenantID": tenantId}
        if returnURL is not None and returnURL != "":
            res["redirectURL"] = returnURL
        return res

    def start(self, tenantId: str, returnURL: str = None) -> dict:
        """
        Docs
        """
        if tenantId is None or tenantId == "":
            raise AuthException(500, "Invalid argument", "TenantID cannot be empty")

        if returnURL is None or returnURL == "":
            raise AuthException(500, "Invalid argument", "ReturnURL cannot be empty")

        uri = EndpointsV1.authSAMLStart
        params = SAML._compose_start_params(tenantId, returnURL)
        response = self._auth_helper.do_get(uri, None, params)

        return response.json()  # Response should be URL
