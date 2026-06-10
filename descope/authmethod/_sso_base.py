# This is not part of the public API but a code helper
from __future__ import annotations

from typing import Any, Dict, Optional

from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class SSOBase:
    """Shared, I/O-free base for SSO auth-method classes.

    Holds only static validation guards and body/params composers — no network I/O, no
    ``__init__``.  The two concrete subclasses add the network layer:

    - ``SSO(SSOBase, AuthBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``SSOAsync(SSOBase, AsyncAuthBase)`` — async, uses ``self._http`` (``HTTPClientAsync``)
    """

    @staticmethod
    def _validate_tenant(tenant: str) -> None:
        if not tenant:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Tenant cannot be empty")

    @staticmethod
    def _compose_start_params(
        tenant: str,
        return_url: str,
        prompt: str,
        sso_id: str,
        login_hint: str,
        force_authn: Optional[bool],
    ) -> dict:
        res: Dict[str, Any] = {"tenant": tenant}
        if return_url is not None and return_url != "":
            res["redirectURL"] = return_url
        if prompt is not None and prompt != "":
            res["prompt"] = prompt
        if sso_id is not None and sso_id != "":
            res["ssoId"] = sso_id
        if login_hint is not None and login_hint != "":
            res["loginHint"] = login_hint
        if force_authn is not None:
            res["forceAuthn"] = force_authn
        return res

    @staticmethod
    def _compose_exchange_body(code: str) -> dict:
        return {"code": code}
