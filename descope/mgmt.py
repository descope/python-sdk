from descope.auth import Auth
from descope.management.tenant import Tenant  # noqa: F401


class MGMT:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth
        self._tenant = Tenant(auth)

    @property
    def tenant(self):
        return self._tenant
