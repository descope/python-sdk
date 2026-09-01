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

    @staticmethod
    def _compose_patch_body(
        id: str,
        name: Optional[str] = None,
        self_provisioning_domains: Optional[List[str]] = None,
        custom_attributes: Optional[dict] = None,
        disabled: Optional[bool] = None,
        enforce_sso: Optional[bool] = None,
        enforce_sso_exclusions: Optional[List[str]] = None,
        federated_app_ids: Optional[List[str]] = None,
        role_inheritance: Optional[str] = None,
    ) -> dict:
        body: dict[str, Any] = {"id": id}
        if name is not None:
            body["name"] = name
        if self_provisioning_domains is not None:
            body["selfProvisioningDomains"] = self_provisioning_domains
        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes
        if disabled is not None:
            body["disabled"] = disabled
        if enforce_sso is not None:
            body["enforceSSO"] = enforce_sso
        if enforce_sso_exclusions is not None:
            body["enforceSSOExclusions"] = enforce_sso_exclusions
        if federated_app_ids is not None:
            body["federatedAppIds"] = federated_app_ids
        if role_inheritance is not None:
            body["roleInheritance"] = role_inheritance
        return body
