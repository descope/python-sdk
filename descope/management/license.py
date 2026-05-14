from __future__ import annotations

from descope._http_base import HTTPBase
from descope.management.common import MgmtV1


class License(HTTPBase):
    def get(self) -> dict:
        """
        Fetch the rate limit tier for the project's company license.

        Returns a dict with a ``rateLimitTier`` field whose value is one of
        ``tier1`` (free), ``tier2`` (pro), ``tier3`` (growth), or ``tier4``
        (enterprise). The SDK sends this value in the ``x-descope-license``
        header on every management request so Cloudflare can apply the right
        rate limit bucket.
        """
        response = self._http.get(MgmtV1.license_get_path)
        return response.json()
