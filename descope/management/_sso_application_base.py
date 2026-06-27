# This is not part of the public API but a code helper
from __future__ import annotations

from typing import Any, List, Optional

from descope.management.common import (
    SAMLIDPAttributeMappingInfo,
    SAMLIDPGroupsMappingInfo,
    saml_idp_attribute_mapping_info_to_dict,
    saml_idp_groups_mapping_info_to_dict,
)


class SSOApplicationBase:
    """Shared, I/O-free base for SSOApplication management classes.

    Holds only static body composers — no network I/O, no ``__init__``.
    The two concrete subclasses add the network layer:

    - ``SSOApplication(SSOApplicationBase, HTTPBase)`` — sync
    - ``SSOApplicationAsync(SSOApplicationBase, AsyncHTTPBase)`` — async
    """

    @staticmethod
    def _compose_create_update_oidc_body(
        name: str,
        login_page_url: str,
        id: Optional[str] = None,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        enabled: Optional[bool] = True,
        force_authentication: Optional[bool] = False,
    ) -> dict:
        body: dict[str, Any] = {
            "name": name,
            "id": id,
            "description": description,
            "logo": logo,
            "enabled": enabled,
            "loginPageUrl": login_page_url,
            "forceAuthentication": force_authentication,
        }
        return body

    @staticmethod
    def _compose_create_update_saml_body(
        name: str,
        login_page_url: str,
        id: Optional[str] = None,
        description: Optional[str] = None,
        enabled: Optional[bool] = True,
        logo: Optional[str] = None,
        use_metadata_info: Optional[bool] = False,
        metadata_url: Optional[str] = None,
        entity_id: Optional[str] = None,
        acs_url: Optional[str] = None,
        certificate: Optional[str] = None,
        attribute_mapping: Optional[List[SAMLIDPAttributeMappingInfo]] = None,
        groups_mapping: Optional[List[SAMLIDPGroupsMappingInfo]] = None,
        acs_allowed_callbacks: Optional[List[str]] = None,
        subject_name_id_type: Optional[str] = None,
        subject_name_id_format: Optional[str] = None,
        default_relay_state: Optional[str] = None,
        force_authentication: Optional[bool] = False,
        logout_redirect_url: Optional[str] = None,
        default_signature_algorithm: Optional[str] = None,
    ) -> dict:
        body: dict[str, Any] = {
            "id": id,
            "name": name,
            "description": description,
            "enabled": enabled,
            "logo": logo,
            "loginPageUrl": login_page_url,
            "useMetadataInfo": use_metadata_info,
            "metadataUrl": metadata_url,
            "entityId": entity_id,
            "acsUrl": acs_url,
            "certificate": certificate,
            "attributeMapping": saml_idp_attribute_mapping_info_to_dict(attribute_mapping),
            "groupsMapping": saml_idp_groups_mapping_info_to_dict(groups_mapping),
            "acsAllowedCallbacks": acs_allowed_callbacks,
            "subjectNameIdType": subject_name_id_type,
            "subjectNameIdFormat": subject_name_id_format,
            "defaultRelayState": default_relay_state,
            "forceAuthentication": force_authentication,
            "logoutRedirectUrl": logout_redirect_url,
            "defaultSignatureAlgorithm": default_signature_algorithm,
        }
        return body
