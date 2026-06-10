# This is not part of the public API but a code helper
from __future__ import annotations

from typing import Optional

from descope.common import LoginOptions


class WebAuthnBase:
    """Shared, I/O-free base for WebAuthn auth-method classes.

    Holds only static body composers — no network I/O, no ``__init__``.
    The two concrete subclasses add the network layer:

    - ``WebAuthn(WebAuthnBase, AuthBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``WebAuthnAsync(WebAuthnBase, AsyncAuthBase)`` — async, uses ``self._http`` (``HTTPClientAsync``)
    """

    @staticmethod
    def _compose_sign_up_start_body(login_id: str, user: dict, origin: str) -> dict:
        user.update({"loginId": login_id})
        return {"user": user, "origin": origin}

    @staticmethod
    def _compose_sign_in_start_body(login_id: str, origin: str, login_options: Optional[LoginOptions] = None) -> dict:
        return {
            "loginId": login_id,
            "origin": origin,
            "loginOptions": login_options.__dict__ if login_options else {},
        }

    @staticmethod
    def _compose_sign_up_or_in_start_body(login_id: str, origin: str) -> dict:
        return {"loginId": login_id, "origin": origin}

    @staticmethod
    def _compose_sign_up_in_finish_body(transaction_id: str, response) -> dict:
        return {"transactionId": transaction_id, "response": response}

    @staticmethod
    def _compose_update_start_body(login_id: str, origin: str) -> dict:
        body: dict = {"loginId": login_id}
        if origin:
            body["origin"] = origin
        return body

    @staticmethod
    def _compose_update_finish_body(transaction_id: str, response: str) -> dict:
        return {"transactionId": transaction_id, "response": response}
