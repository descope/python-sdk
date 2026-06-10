# This is not part of the public API but a code helper
from __future__ import annotations


class OAuthBase:
    """Shared, I/O-free base for OAuth auth-method classes.

    Holds only static validation guards and body/params composers — no network I/O, no
    ``__init__``.  The two concrete subclasses add the network layer:

    - ``OAuth(OAuthBase, AuthBase)`` — sync, uses ``self._http`` (``HTTPClient``)
    - ``OAuthAsync(OAuthBase, AsyncAuthBase)`` — async, uses ``self._http`` (``HTTPClientAsync``)
    """

    @staticmethod
    def _verify_provider(oauth_provider: str) -> bool:
        if oauth_provider == "" or oauth_provider is None:
            return False
        return True

    @staticmethod
    def _compose_start_params(provider: str, return_url: str = "") -> dict:
        res: dict = {"provider": provider}
        if return_url:
            res["redirectURL"] = return_url
        return res

    @staticmethod
    def _compose_exchange_body(code: str) -> dict:
        return {"code": code}
