# This is not part of the public API but a code helper
from __future__ import annotations

from typing import Optional

from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.management.common import MgmtUserRequest, MgmtSignUpOptions


class JWTBase:
    """Shared, I/O-free base for JWT management classes.

    Holds only static validation guards and body composers — no network I/O, no
    ``__init__``.  The two concrete subclasses add the network layer:

    - ``JWT(JWTBase, HTTPBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``JWTAsync(JWTBase, AsyncHTTPBase)`` — async, uses ``self._http`` (``HTTPClientAsync``)
    """

    @staticmethod
    def _validate_jwt(jwt: str) -> None:
        if not jwt:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "jwt cannot be empty")

    @staticmethod
    def _validate_impersonator_id(impersonator_id: str) -> None:
        if not impersonator_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "impersonator_id cannot be empty")

    @staticmethod
    def _validate_login_id(login_id: str) -> None:
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty")

    @staticmethod
    def _validate_jwt_required(login_options) -> None:
        if not login_options.jwt:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "JWT is required")

    @staticmethod
    def _compose_sign_up_body(
        login_id: str,
        user: MgmtUserRequest,
        signup_options: MgmtSignUpOptions,
    ) -> dict:
        return {
            "loginId": login_id,
            "user": user.to_dict(),
            "emailVerified": user.email_verified,
            "phoneVerified": user.phone_verified,
            "ssoAppId": user.sso_app_id,
            "customClaims": signup_options.custom_claims,
            "refreshDuration": signup_options.refresh_duration,
        }
