from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
)
from descope.exceptions import AuthException
from descope.authhelper import AuthHelper

class SAML():
    def __init__(self, auth_helper):
        self._auth_helper = auth_helper
    