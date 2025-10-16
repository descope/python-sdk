# This is not part of the public API but a code helper
from descope.auth import Auth


# XXX in the future we can remove this class entirely and have auth methods be base HTTPBase instead
class AuthBase:
    """Base class for classes having auth"""

    def __init__(self, auth: Auth):
        self._auth = auth
        self._http = auth.http_client
