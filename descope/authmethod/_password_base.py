# This is not part of the public API but a code helper
from __future__ import annotations


class PasswordBase:
    """Shared, I/O-free base for Password auth-method classes.

    Holds only static body composers — no network I/O, no ``__init__``.
    The two concrete subclasses add the network layer:

    - ``Password(PasswordBase, AuthBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``PasswordAsync(PasswordBase, AsyncAuthBase)`` — async, uses ``self._http`` (``HTTPClientAsync``)
    """

    @staticmethod
    def _compose_signup_body(login_id: str, password: str, user: dict | None) -> dict:
        body: dict[str, str | bool | dict] = {"loginId": login_id, "password": password}
        if user is not None:
            body["user"] = user
        return body
