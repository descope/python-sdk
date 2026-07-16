from __future__ import annotations

from typing import Any, Optional

from descope.management.outbound_scim_types import OutboundSCIMConfigurationData


class OutboundSCIMBase:
    @staticmethod
    def _compose_create_body(
        app_id: str,
        configuration: Optional[OutboundSCIMConfigurationData] = None,
    ) -> dict:
        body: dict[str, Any] = {
            "appId": app_id,
        }
        if configuration is not None:
            body["configuration"] = configuration
        return body

    @staticmethod
    def _compose_update_body(
        app_id: str,
        version: int,
        configuration: Optional[OutboundSCIMConfigurationData] = None,
    ) -> dict:
        body: dict[str, Any] = {
            "appId": app_id,
            "version": version,
        }
        if configuration is not None:
            body["configuration"] = configuration
        return body
