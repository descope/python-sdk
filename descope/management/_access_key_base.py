# This is not part of the public API but a code helper
from __future__ import annotations

from typing import List, Optional

from descope.management.common import AssociatedTenant, associated_tenants_to_dict


class AccessKeyBase:
    """Shared, I/O-free base for AccessKey management classes.

    Holds only static body composers — no network I/O, no ``__init__``.
    The two concrete subclasses add the network layer:

    - ``AccessKey(AccessKeyBase, HTTPBase)`` — sync
    - ``AccessKeyAsync(AccessKeyBase, AsyncHTTPBase)`` — async
    """

    @staticmethod
    def _compose_create_body(
        name: str,
        expire_time: int,
        role_names: List[str],
        key_tenants: List[AssociatedTenant],
        user_id: Optional[str] = None,
        custom_claims: Optional[dict] = None,
        description: Optional[str] = None,
        permitted_ips: Optional[List[str]] = None,
        custom_attributes: Optional[dict] = None,
    ) -> dict:
        return {
            "name": name,
            "expireTime": expire_time,
            "roleNames": role_names,
            "keyTenants": associated_tenants_to_dict(key_tenants),
            "userId": user_id,
            "customClaims": custom_claims,
            "description": description,
            "permittedIps": permitted_ips,
            "customAttributes": custom_attributes,
        }
