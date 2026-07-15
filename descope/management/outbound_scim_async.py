from __future__ import annotations

from typing import Optional

from descope._http_base import AsyncHTTPBase
from descope.management._outbound_scim_base import OutboundSCIMBase
from descope.management.common import MgmtV1


class OutboundSCIMAsync(OutboundSCIMBase, AsyncHTTPBase):
    """Async counterpart of OutboundSCIM — all HTTP calls are coroutines."""

    async def create_configuration(
        self,
        app_id: str,
        configuration: Optional[dict] = None,
    ) -> dict:
        """
        Create a new outbound SCIM configuration on the federated SSO application
        identified by app_id. The connector name is derived server-side from the app.

        Args:
        app_id (str): The federated SSO application id this SCIM configuration binds to.
        configuration (dict): Optional provider-specific SCIM configuration dictionary.

        Return value (dict):
        Return dict in the format
             {"configuration": {"appId": <app_id>, "configuration": {...},
                                "enabled": <bool>, "lastExportTime": <int>,
                                "lastProcessingTime": <int>, "failures": <int>,
                                "version": <int>}}

        Raise:
        AuthException: raised if create operation fails
        """
        response = await self._http.post(
            MgmtV1.outbound_scim_create_path,
            body=OutboundSCIMBase._compose_create_body(app_id, configuration),
        )
        return response.json()

    async def update_configuration(
        self,
        app_id: str,
        version: int,
        configuration: Optional[dict] = None,
    ) -> dict:
        """
        Update the outbound SCIM configuration attached to the given federated SSO app.
        The version must match the currently stored version — otherwise the update is
        rejected as a conflict.

        Args:
        app_id (str): The federated SSO application id.
        version (int): The currently stored version, used for optimistic concurrency.
        configuration (dict): Optional updated provider-specific SCIM configuration.

        Return value (dict):
        Return dict in the format
             {"configuration": {"appId": <app_id>, ...}}

        Raise:
        AuthException: raised if update operation fails
        """
        response = await self._http.post(
            MgmtV1.outbound_scim_update_path,
            body=OutboundSCIMBase._compose_update_body(app_id, version, configuration),
        )
        return response.json()

    async def delete_configuration(
        self,
        app_id: str,
    ):
        """
        Delete the outbound SCIM configuration attached to the given federated SSO app.
        IMPORTANT: This action is irreversible. Use carefully.

        Args:
        app_id (str): The federated SSO application id.

        Raise:
        AuthException: raised if deletion operation fails
        """
        await self._http.post(MgmtV1.outbound_scim_delete_path, body={"appId": app_id})

    async def load_configuration(
        self,
        app_id: str,
    ) -> dict:
        """
        Load the outbound SCIM configuration attached to the given federated SSO app.

        Args:
        app_id (str): The federated SSO application id.

        Return value (dict):
        Return dict in the format
             {"configuration": {"appId": <app_id>, "configuration": {...},
                                "enabled": <bool>, "lastExportTime": <int>,
                                "lastProcessingTime": <int>, "failures": <int>,
                                "version": <int>}}

        Raise:
        AuthException: raised if load operation fails
        """
        response = await self._http.get(f"{MgmtV1.outbound_scim_load_path}/{app_id}")
        return response.json()

    async def set_enabled(
        self,
        app_id: str,
        enabled: bool,
    ) -> dict:
        """
        Enable or disable the outbound SCIM configuration attached to the given
        federated SSO app.

        Args:
        app_id (str): The federated SSO application id.
        enabled (bool): Whether the SCIM configuration should be enabled.

        Return value (dict):
        Return dict in the format
             {"configuration": {"appId": <app_id>, "enabled": <bool>, ...}}

        Raise:
        AuthException: raised if the operation fails
        """
        response = await self._http.post(
            MgmtV1.outbound_scim_set_enabled_path,
            body={"appId": app_id, "enabled": enabled},
        )
        return response.json()
