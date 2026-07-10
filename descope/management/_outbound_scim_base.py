from __future__ import annotations

from typing import Any, Optional


class OutboundSCIMBase:
    @staticmethod
    def _compose_create_body(
        name: str,
        app_id: str,
        configuration: Optional[dict] = None,
    ) -> dict:
        body: dict[str, Any] = {
            "name": name,
            "appId": app_id,
        }
        if configuration is not None:
            body["configuration"] = configuration
        return body

    @staticmethod
    def _compose_update_body(
        id: str,
        version: int,
        configuration: Optional[dict] = None,
        name: Optional[str] = None,
    ) -> dict:
        body: dict[str, Any] = {
            "id": id,
            "version": version,
        }
        if name is not None:
            body["name"] = name
        if configuration is not None:
            body["configuration"] = configuration
        return body
