from ssl import SSLContext


class SSLMatcher:
    """Matcher for the `verify=` kwarg passed to httpx.* calls in tests.

    Default: matches any ssl.SSLContext (secure=True clients).
    Use SSLMatcher(insecure=True) to match `verify=False` (secure=False clients).
    """

    def __init__(self, insecure: bool = False):
        self._insecure = insecure

    def __eq__(self, other):
        if self._insecure:
            return other is False
        return isinstance(other, SSLContext)

    def __repr__(self):
        return f"SSLMatcher(insecure={self._insecure})" if self._insecure else "SSLMatcher()"
