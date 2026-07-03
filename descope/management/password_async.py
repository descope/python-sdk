from __future__ import annotations

from descope._http_base import AsyncHTTPBase
from descope.management.common import MgmtV1


class PasswordAsync(AsyncHTTPBase):
    """Async counterpart of Password — all HTTP calls are coroutines."""

    async def get_settings(self, tenant_id: str = "") -> dict:
        """
        Get password settings for the project or a specific tenant.

        Args:
        tenant_id (str): Optional tenant ID. If empty, returns project-level settings.

        Return value (dict):
        Return dict in the format
             {
                "enabled": bool,
                "minLength": int,
                "lowercase": bool,
                "uppercase": bool,
                "number": bool,
                "nonAlphanumeric": bool,
                "expiration": bool,
                "expirationWeeks": int,
                "reuse": bool,
                "reuseAmount": int,
                "lock": bool,
                "lockAttempts": int
             }

        Raise:
        AuthException: raised if get operation fails
        """
        params = {"tenantId": tenant_id}
        response = await self._http.get(MgmtV1.password_settings_path, params=params)
        return response.json()

    async def configure_settings(self, tenant_id: str, settings: dict):
        """
        Configure password settings for the project or a specific tenant.

        Args:
        tenant_id (str): Tenant ID. Empty string for project-level settings.
        settings (dict): Password settings dict with keys:
            - enabled (bool): Whether password authentication is enabled
            - minLength (int): Minimum password length
            - lowercase (bool): Require lowercase characters
            - uppercase (bool): Require uppercase characters
            - number (bool): Require numeric characters
            - nonAlphanumeric (bool): Require non-alphanumeric characters
            - expiration (bool): Enable password expiration
            - expirationWeeks (int): Number of weeks until password expires
            - reuse (bool): Enable password reuse prevention
            - reuseAmount (int): Number of previous passwords to prevent reuse
            - lock (bool): Enable account locking after failed attempts
            - lockAttempts (int): Number of failed attempts before locking

        Raise:
        AuthException: raised if configure operation fails
        """
        body = {"tenantId": tenant_id, **settings}
        await self._http.post(MgmtV1.password_settings_path, body=body)
