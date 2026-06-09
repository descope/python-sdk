from ssl import SSLContext

# Test fixtures: ES384 key + JWTs signed with kid=P2CuC9yv2UGtGI1o84gCZEb9qEQW
PUBLIC_KEY_DICT = {
    "alg": "ES384",
    "crv": "P-384",
    "kid": "P2CuC9yv2UGtGI1o84gCZEb9qEQW",
    "kty": "EC",
    "use": "sig",
    "x": "DCjjyS7blnEmenLyJVwmH6yMnp7MlEggfk1kLtOv_Khtpps_Mq4K9brqsCwQhGUP",
    "y": "xKy4IQ2FaLEzrrl1KE5mKbioLhj1prYFk1itdTOr6Xpy1fgq86kC7v-Y2F2vpcDc",
}

# drn=DSR, exp=2264443061 (far future)
VALID_REFRESH_TOKEN = (
    "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ"
    ".eyJkcm4iOiJEU1IiLCJleHAiOjIyNjQ0NDMwNjEsImlhdCI6MTY1OTY0MzA2MSwiaXNzIjoiUDJDdUM5eXYy"
    "VUd0R0kxbzg0Z0NaRWI5cUVRVyIsInN1YiI6IlUyQ3VDUHVKZ1BXSEdCNVA0R21mYnVQR2hHVm0ifQ"
    ".mRo9FihYMR3qnQT06Mj3CJ5X0uTCEcXASZqfLLUv0cPCLBtBqYTbuK-ZRDnV4e4N6zGCNX2a3jjpbyqbViOx"
    "ICCNSxJsVb-sdsSujtEXwVMsTTLnpWmNsMbOUiKmoME0"
)

# drn=DS, exp=2493061415 (far future)
VALID_SESSION_TOKEN = (
    "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ"
    ".eyJkcm4iOiJEUyIsImV4cCI6MjQ5MzA2MTQxNSwiaWF0IjoxNjU5NjQzMDYxLCJpc3MiOiJQMkN1Qzl5djJVR3"
    "RHSTFvODRnQ1pFYjlxRVFXIiwic3ViIjoiVTJDdUNQdUpnUFdIR0I1UDRHbWZidVBHaEdWbSJ9"
    ".gMalOv1GhqYVsfITcOc7Jv_fibX1Iof6AFy2KCVmyHmU2KwATT6XYXsHjBFFLq262Pg-LS1IX9f_DV3ppzvb1p"
    "SY4ccsP6WDGd1vJpjp3wFBP9Sji6WXL0SCCJUFIyJR"
)

# drn=DS, exp=1659644298 (past — use for expiry tests)
EXPIRED_SESSION_TOKEN = (
    "eyJhbGciOiJFUzM4NCIsImtpZCI6IlAyQ3VDOXl2MlVHdEdJMW84NGdDWkViOXFFUVciLCJ0eXAiOiJKV1QifQ"
    ".eyJkcm4iOiJEUyIsImV4cCI6MTY1OTY0NDI5OCwiaWF0IjoxNjU5NjQ0Mjk3LCJpc3MiOiJQMkN1Qzl5djJVR3"
    "RHSTFvODRnQ1pFYjlxRVFXIiwic3ViIjoiVTJDdUNQdUpnUFdIR0I1UDRHbWZidVBHaEdWbSJ9"
    ".wBuOnIQI_z3SXOszqsWCg8ilOPdE5ruWYHA3jkaeQ3uX9hWgCTd69paFajc-xdMYbqlIF7JHji7T9oVmkCUJvD"
    "NgRZRZO9boMFANPyXitLOK4aX3VZpMJBpFxdrWV3GE"
)


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
