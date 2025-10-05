from ssl import SSLContext


class SSLMatcher:
    def __eq__(self, other):
        return isinstance(other, SSLContext)
