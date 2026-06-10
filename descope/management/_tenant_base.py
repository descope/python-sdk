from __future__ import annotations

from typing import Any, List, Optional


class TenantBase:
    @staticmethod
    def _compose_create_update_body(
        name: str,
        id: Optional[str],
        self_provisioning_domains: List[str],
        custom_attributes: Optional[dict] = None,
        enforce_sso: Optional[bool] = False,
        enforce_sso_exclusions: Optional[List[str]] = None,
        federated_app_ids: Optional[List[str]] = None,
        disabled: Optional[bool] = False,
    ) -> dict:
        body: dict[str, Any] = {
            "name": name,
            "id": id,
            "selfProvisioningDomains": self_provisioning_domains,
            "enforceSSO": enforce_sso,
            "disabled": disabled,
        }
        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes
        if enforce_sso_exclusions is not None:
            body["enforceSSOExclusions"] = enforce_sso_exclusions
        if federated_app_ids is not None:
            body["federatedAppIds"] = federated_app_ids
        return body
