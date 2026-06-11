# This is not part of the public API but a code helper
from __future__ import annotations

from typing import Optional

from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class SAMLBase:
    """Shared, I/O-free base for SAML auth-method classes (deprecated — use SSO).

    Holds only static validation guards and body/params composers — no network I/O, no
    ``__init__``.  The two concrete subclasses add the network layer:

    - ``SAML(SAMLBase, AuthBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``SAMLAsync(SAMLBase, AsyncAuthBase)`` — async, uses ``self._http`` (``HTTPClientAsync``)
    """

    @staticmethod
    def _validate_tenant(tenant: str) -> None:
        if not tenant:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Tenant cannot be empty")

    @staticmethod
    def _validate_return_url(return_url: Optional[str]) -> None:
        if not return_url:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Return url cannot be empty")

    @staticmethod
    def _validate_exchange_code(code: str) -> None:
        if not code:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "exchange code is empty")

    @staticmethod
    def _compose_start_params(tenant: str, return_url: Optional[str]) -> dict:
        res: dict = {"tenant": tenant}
        if return_url is not None and return_url != "":
            res["redirectURL"] = return_url
        return res

    @staticmethod
    def _compose_exchange_body(code: str) -> dict:
        return {"code": code}
