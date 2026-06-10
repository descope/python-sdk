# This is not part of the public API but a code helper
from __future__ import annotations

from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class PasswordBase:
    """Shared, I/O-free base for Password auth-method classes.

    Holds only static validation guards and body composers — no network I/O, no
    ``__init__``.  The two concrete subclasses add the network layer:

    - ``Password(PasswordBase, AuthBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``PasswordAsync(PasswordBase, AsyncAuthBase)`` — async, uses ``self._http`` (``HTTPClientAsync``)
    """

    @staticmethod
    def _validate_login_id(login_id: str) -> None:
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty")

    @staticmethod
    def _validate_password(password: str) -> None:
        if not password:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "password cannot be empty")

    @staticmethod
    def _validate_sign_in_password(password: str) -> None:
        if not password:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Password cannot be empty")

    @staticmethod
    def _validate_new_password(new_password: str) -> None:
        if not new_password:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "new_password cannot be empty")

    @staticmethod
    def _validate_old_password(old_password: str) -> None:
        if not old_password:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "old_password cannot be empty")

    @staticmethod
    def _validate_refresh_token(refresh_token: str) -> None:
        if not refresh_token:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Refresh token cannot be empty")

    @staticmethod
    def _compose_signup_body(login_id: str, password: str, user: dict | None) -> dict:
        body: dict[str, str | bool | dict] = {"loginId": login_id, "password": password}
        if user is not None:
            body["user"] = user
        return body
