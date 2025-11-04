# This is not part of the public API but a code helper
from descope.auth import Auth


class AuthBase:
    """Base class for classes having auth"""

    def __init__(self, auth: Auth):
        self._auth = auth
        self._http = auth.http_client
