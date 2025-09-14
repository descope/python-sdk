from __future__ import annotations

from typing import Callable, Iterable, Optional

import jwt

from descope.common import (
    COOKIE_DATA_NAME,
    REFRESH_SESSION_TOKEN_NAME,
    SESSION_TOKEN_NAME,
)


def adjust_properties(jwt_response: dict, user_jwt: bool) -> dict:
    """Normalize top-level fields on a JWT response.

    Copies permissions/roles/tenants from present token claims (session or refresh)
    to the top-level and sets projectId and userId/keyId for convenience.
    """
    # Save permissions, roles and tenants info from Session token or from refresh token on the json top level
    if SESSION_TOKEN_NAME in jwt_response:
        jwt_response["permissions"] = jwt_response[SESSION_TOKEN_NAME].get(
            "permissions", []
        )
        jwt_response["roles"] = jwt_response[SESSION_TOKEN_NAME].get("roles", [])
        jwt_response["tenants"] = jwt_response[SESSION_TOKEN_NAME].get("tenants", {})
    elif REFRESH_SESSION_TOKEN_NAME in jwt_response:
        jwt_response["permissions"] = jwt_response[REFRESH_SESSION_TOKEN_NAME].get(
            "permissions", []
        )
        jwt_response["roles"] = jwt_response[REFRESH_SESSION_TOKEN_NAME].get(
            "roles", []
        )
        jwt_response["tenants"] = jwt_response[REFRESH_SESSION_TOKEN_NAME].get(
            "tenants", {}
        )
    else:
        jwt_response["permissions"] = jwt_response.get("permissions", [])
        jwt_response["roles"] = jwt_response.get("roles", [])
        jwt_response["tenants"] = jwt_response.get("tenants", {})

    # Save the projectID also in the dict top level
    issuer = (
        jwt_response.get(SESSION_TOKEN_NAME, {}).get("iss", None)
        or jwt_response.get(REFRESH_SESSION_TOKEN_NAME, {}).get("iss", None)
        or jwt_response.get("iss", "")
    )
    jwt_response["projectId"] = issuer.rsplit("/")[
        -1
    ]  # support both url issuer and project ID issuer

    sub = (
        jwt_response.get(SESSION_TOKEN_NAME, {}).get("dsub", None)
        or jwt_response.get(SESSION_TOKEN_NAME, {}).get("sub", None)
        or jwt_response.get(REFRESH_SESSION_TOKEN_NAME, {}).get("dsub", None)
        or jwt_response.get(REFRESH_SESSION_TOKEN_NAME, {}).get("sub", None)
        or jwt_response.get("sub", "")
    )
    if user_jwt:
        # Save the userID also in the dict top level
        jwt_response["userId"] = sub
    else:
        # Save the AccessKeyID also in the dict top level
        jwt_response["keyId"] = sub

    return jwt_response


def decode_token_unverified(
    token: str, audience: Optional[str | Iterable[str]] = None
) -> dict:
    """Decode a JWT without verifying signature (used when no validator is provided).

    Audience verification is disabled by default since no key is provided.
    Returns an empty dict if decoding fails.
    """
    try:
        return jwt.decode(
            token, options={"verify_signature": False, "verify_aud": False}
        )
    except Exception:
        return {}


def generate_auth_info(
    response_body: dict,
    refresh_token: Optional[str],
    user_jwt: bool,
    audience: Optional[str | Iterable[str]] = None,
    token_validator: Optional[
        Callable[[str, Optional[str | Iterable[str]]], dict]
    ] = None,
) -> dict:
    """Build the normalized JWT info dict using a provided token validator.

    token_validator should accept (token, audience) and return decoded claims dict.
    If not provided, tokens will be decoded without signature verification.
    """
    if token_validator is None:
        token_validator = decode_token_unverified

    jwt_response: dict = {}

    st_jwt = response_body.get("sessionJwt", "")
    if st_jwt:
        jwt_response[SESSION_TOKEN_NAME] = token_validator(st_jwt, audience)

    rt_jwt = response_body.get("refreshJwt", "")
    if rt_jwt:
        jwt_response[REFRESH_SESSION_TOKEN_NAME] = token_validator(rt_jwt, audience)
    elif refresh_token:
        jwt_response[REFRESH_SESSION_TOKEN_NAME] = token_validator(
            refresh_token, audience
        )

    jwt_response = adjust_properties(jwt_response, user_jwt)

    if user_jwt:
        jwt_response[COOKIE_DATA_NAME] = {
            "exp": response_body.get("cookieExpiration", 0),
            "maxAge": response_body.get("cookieMaxAge", 0),
            "domain": response_body.get("cookieDomain", ""),
            "path": response_body.get("cookiePath", "/"),
        }

    return jwt_response


def generate_jwt_response(
    response_body: dict,
    refresh_cookie: Optional[str],
    audience: Optional[str | Iterable[str]] = None,
    token_validator: Optional[
        Callable[[str, Optional[str | Iterable[str]]], dict]
    ] = None,
) -> dict:
    """Compose the final JWT response body using the provided token validator."""
    jwt_response = generate_auth_info(
        response_body, refresh_cookie, True, audience, token_validator
    )
    jwt_response["user"] = response_body.get("user", {})
    jwt_response["firstSeen"] = response_body.get("firstSeen", True)
    return jwt_response
