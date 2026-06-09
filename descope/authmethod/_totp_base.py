# This is not part of the public API but a code helper
from __future__ import annotations

from typing import Optional

from descope.common import LoginOptions
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class TOTPBase:
    """Shared, I/O-free base for TOTP auth-method classes.

    Holds only static validation guards and body composers — no network I/O, no
    ``__init__``.  The two concrete subclasses add the network layer:

    - ``TOTP(TOTPBase, AuthBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``AsyncTOTP(TOTPBase, AsyncAuthBase)`` — async, uses ``self._http`` (``AsyncHTTPClient``)
    """

    @staticmethod
    def _validate_login_id(login_id: str) -> None:
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty")

    @staticmethod
    def _validate_code(code: str) -> None:
        if not code:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Code cannot be empty")

    @staticmethod
    def _validate_refresh_token(refresh_token: str) -> None:
        if not refresh_token:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Refresh token cannot be empty")

    @staticmethod
    def _compose_signup_body(login_id: str, user: Optional[dict]) -> dict:
        body: dict[str, str | dict] = {"loginId": login_id}
        if user is not None:
            body["user"] = user
        return body

    @staticmethod
    def _compose_signin_body(login_id: str, code: str, login_options: Optional[LoginOptions] = None) -> dict:
        return {
            "loginId": login_id,
            "code": code,
            "loginOptions": login_options.__dict__ if login_options else {},
        }

    @staticmethod
    def _compose_update_user_body(login_id: str) -> dict:
        return {"loginId": login_id}
