import unittest

from descope.jwt_common import (
    COOKIE_DATA_NAME,
    REFRESH_SESSION_TOKEN_NAME,
    SESSION_TOKEN_NAME,
    decode_token_unverified,
    generate_jwt_response,
)


class TestJwtCommon(unittest.TestCase):
    def test_generate_jwt_response_sets_user_and_first_seen_and_cookie(self):
        # Arrange: a response body with cookie and user fields
        response_body = {
            "sessionJwt": "token1",
            # do not provide refreshJwt to exercise refresh_cookie fallback
            "cookieExpiration": 123,
            "cookieMaxAge": 456,
            "cookieDomain": "example.com",
            "cookiePath": "/test",
            "user": {"name": "Ada"},
            "firstSeen": False,
        }

        def validator(token: str, audience=None):
            # Return different iss/sub based on which token is being validated
            if token == "token1":
                return {"iss": "https://issuer.example/P123", "sub": "user-1"}
            # refresh cookie fallback
            return {"iss": "https://issuer.example/P999", "sub": "user-2"}

        # Act
        jwt_response = generate_jwt_response(
            response_body,
            refresh_cookie="token2",
            audience=None,
            token_validator=validator,
        )

        # Assert top-level fields
        assert jwt_response["user"] == {"name": "Ada"}
        assert jwt_response["firstSeen"] is False
        # Project ID should be parsed from issuer (last path segment)
        assert jwt_response["projectId"] == "P123"
        # userId copied from session token sub
        assert jwt_response["userId"] == "user-1"
        # cookie data present
        assert jwt_response[COOKIE_DATA_NAME] == {
            "exp": 123,
            "maxAge": 456,
            "domain": "example.com",
            "path": "/test",
        }
        # both tokens should be decoded (session from body, refresh from cookie)
        assert SESSION_TOKEN_NAME in jwt_response
        assert REFRESH_SESSION_TOKEN_NAME in jwt_response

    def test_decode_token_unverified_handles_garbage(self):
        # Invalid token strings should not raise and should return empty dict
        assert decode_token_unverified("not-a-jwt") == {}


if __name__ == "__main__":
    unittest.main()
