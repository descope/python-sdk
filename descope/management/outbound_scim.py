from __future__ import annotations

from typing import Optional

from descope._http_base import HTTPBase
from descope.management._outbound_scim_base import OutboundSCIMBase
from descope.management.common import MgmtV1


class OutboundSCIM(OutboundSCIMBase, HTTPBase):
    def create_configuration(
        self,
        name: str,
        app_id: str,
        configuration: Optional[dict] = None,
    ) -> dict:
        """
        Create a new outbound SCIM configuration. The configuration ID is provisioned
        automatically by Descope and returned in the response.

        Args:
        name (str): The outbound SCIM configuration's name.
        app_id (str): The ID of the outbound application this SCIM configuration binds to.
        configuration (dict): Optional provider-specific SCIM configuration dictionary.

        Return value (dict):
        Return dict in the format
             {"configuration": {"id": <id>, "name": <name>, "appId": <app_id>,
                                "configuration": {...}, "enabled": <bool>,
                                "lastExportTime": <int>, "lastProcessingTime": <int>,
                                "failures": <int>, "version": <int>}}

        Raise:
        AuthException: raised if create operation fails
        """
        response = self._http.post(
            MgmtV1.outbound_scim_create_path,
            body=OutboundSCIMBase._compose_create_body(name, app_id, configuration),
        )
        return response.json()

    def update_configuration(
        self,
        id: str,
        version: int,
        configuration: Optional[dict] = None,
        name: Optional[str] = None,
    ) -> dict:
        """
        Update an existing outbound SCIM configuration. The version must match the
        currently stored version — otherwise the update is rejected as a conflict.

        Args:
        id (str): The ID of the outbound SCIM configuration to update.
        version (int): The currently stored version, used for optimistic concurrency.
        configuration (dict): Optional updated provider-specific SCIM configuration.
        name (str): Optional updated configuration name.

        Return value (dict):
        Return dict in the format
             {"configuration": {"id": <id>, "name": <name>, ...}}

        Raise:
        AuthException: raised if update operation fails
        """
        response = self._http.post(
            MgmtV1.outbound_scim_update_path,
            body=OutboundSCIMBase._compose_update_body(id, version, configuration, name),
        )
        return response.json()

    def delete_configuration(
        self,
        id: str,
    ):
        """
        Delete an existing outbound SCIM configuration. IMPORTANT: This action is
        irreversible. Use carefully.

        Args:
        id (str): The ID of the outbound SCIM configuration to delete.

        Raise:
        AuthException: raised if deletion operation fails
        """
        self._http.post(MgmtV1.outbound_scim_delete_path, body={"id": id})

    def load_configuration(
        self,
        id: str,
    ) -> dict:
        """
        Load an outbound SCIM configuration by ID.

        Args:
        id (str): The ID of the outbound SCIM configuration to load.

        Return value (dict):
        Return dict in the format
             {"configuration": {"id": <id>, "name": <name>, "appId": <app_id>,
                                "configuration": {...}, "enabled": <bool>,
                                "lastExportTime": <int>, "lastProcessingTime": <int>,
                                "failures": <int>, "version": <int>}}

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(f"{MgmtV1.outbound_scim_load_path}/{id}")
        return response.json()

    def load_all_configurations(self) -> dict:
        """
        Load all outbound SCIM configurations for the project.

        Return value (dict):
        Return dict in the format
             {"configurations": [{"id": <id>, "name": <name>, ...}, ...]}

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(MgmtV1.outbound_scim_load_all_path)
        return response.json()

    def set_enabled(
        self,
        id: str,
        enabled: bool,
    ) -> dict:
        """
        Enable or disable an outbound SCIM configuration.

        Args:
        id (str): The ID of the outbound SCIM configuration to update.
        enabled (bool): Whether the SCIM configuration should be enabled.

        Return value (dict):
        Return dict in the format
             {"configuration": {"id": <id>, "name": <name>, "enabled": <bool>, ...}}

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._http.post(
            MgmtV1.outbound_scim_set_enabled_path,
            body={"id": id, "enabled": enabled},
        )
        return response.json()
