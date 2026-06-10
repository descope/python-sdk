# This is not part of the public API but a code helper
from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from descope.management.sso_settings import (
        AttributeMapping,
        FGAGroupMapping,
        RoleMapping,
        SSOOIDCSettings,
        SSOSAMLSettings,
        SSOSAMLSettingsByMetadata,
    )


class SSOSettingsBase:
    """Shared, I/O-free base for SSOSettings management classes.

    Holds only static body composers and dict converters — no network I/O, no
    ``__init__``.  The two concrete subclasses add the network layer:

    - ``SSOSettings(SSOSettingsBase, HTTPBase)`` — sync
    - ``SSOSettingsAsync(SSOSettingsBase, AsyncHTTPBase)`` — async
    """

    @staticmethod
    def _compose_configure_body(
        tenant_id: str,
        idp_url: str,
        entity_id: str,
        idp_cert: str,
        redirect_url: str,
        domains: Optional[List[str]],
    ) -> dict:
        return {
            "tenantId": tenant_id,
            "idpURL": idp_url,
            "entityId": entity_id,
            "idpCert": idp_cert,
            "redirectURL": redirect_url,
            "domains": domains,
        }

    @staticmethod
    def _compose_metadata_body(
        tenant_id: str,
        idp_metadata_url: str,
        redirect_url: Optional[str] = None,
        domains: Optional[List[str]] = None,
    ) -> dict:
        return {
            "tenantId": tenant_id,
            "idpMetadataURL": idp_metadata_url,
            "redirectURL": redirect_url,
            "domains": domains,
        }

    @staticmethod
    def _compose_mapping_body(
        tenant_id: str,
        role_mapping: Optional[List[RoleMapping]],
        attribute_mapping: Optional[AttributeMapping],
    ) -> dict:
        return {
            "tenantId": tenant_id,
            "roleMappings": SSOSettingsBase._role_mapping_to_dict(role_mapping),
            "attributeMapping": SSOSettingsBase._attribute_mapping_to_dict(attribute_mapping),
        }

    @staticmethod
    def _role_mapping_to_dict(role_mapping: Optional[List[RoleMapping]]) -> list:
        if role_mapping is None:
            role_mapping = []
        role_mapping_list = []
        for mapping in role_mapping:
            role_mapping_list.append(
                {
                    "groups": mapping.groups,
                    "roleName": mapping.role_name,
                }
            )
        return role_mapping_list

    @staticmethod
    def _attribute_mapping_to_dict(
        attribute_mapping: Optional[AttributeMapping],
    ) -> dict:
        if attribute_mapping is None:
            raise ValueError("Attribute mapping cannot be None")
        return {
            "name": attribute_mapping.name,
            "email": attribute_mapping.email,
            "phoneNumber": attribute_mapping.phone_number,
            "group": attribute_mapping.group,
            "givenName": attribute_mapping.given_name,
            "middleName": attribute_mapping.middle_name,
            "familyName": attribute_mapping.family_name,
            "picture": attribute_mapping.picture,
            "customAttributes": attribute_mapping.custom_attributes,
        }

    @staticmethod
    def _fga_mappings_to_dict(
        fga_mappings: Optional[Dict[str, FGAGroupMapping]],
    ) -> Optional[dict]:
        if fga_mappings is None:
            return None
        result: dict = {}
        for group_name, mapping in fga_mappings.items():
            relations = []
            if mapping is not None and mapping.relations:
                for relation in mapping.relations:
                    relations.append(
                        {
                            "resource": relation.resource,
                            "relationDefinition": relation.relation_definition,
                            "namespace": relation.namespace,
                        }
                    )
            result[group_name] = {"relations": relations}
        return result

    @staticmethod
    def _compose_configure_oidc_settings_body(
        tenant_id: str,
        settings: SSOOIDCSettings,
        domains: Optional[List[str]],
    ) -> dict:
        attr_mapping = None
        if settings.attribute_mapping:
            attr_mapping = {
                "loginId": settings.attribute_mapping.login_id,
                "name": settings.attribute_mapping.name,
                "givenName": settings.attribute_mapping.given_name,
                "middleName": settings.attribute_mapping.middle_name,
                "familyName": settings.attribute_mapping.family_name,
                "email": settings.attribute_mapping.email,
                "verifiedEmail": settings.attribute_mapping.verified_email,
                "username": settings.attribute_mapping.username,
                "phoneNumber": settings.attribute_mapping.phone_number,
                "verifiedPhone": settings.attribute_mapping.verified_phone,
                "picture": settings.attribute_mapping.picture,
            }

        return {
            "tenantId": tenant_id,
            "settings": {
                "name": settings.name,
                "clientId": settings.client_id,
                "clientSecret": settings.client_secret,
                "redirectUrl": settings.redirect_url,
                "authUrl": settings.auth_url,
                "tokenUrl": settings.token_url,
                "userDataUrl": settings.user_data_url,
                "scope": settings.scope,
                "JWKsUrl": settings.jwks_url,
                "userAttrMapping": attr_mapping,
                "manageProviderTokens": settings.manage_provider_tokens,
                "callbackDomain": settings.callback_domain,
                "prompt": settings.prompt,
                "grantType": settings.grant_type,
                "issuer": settings.issuer,
                "groupsPriority": settings.groups_priority,
                "fgaMappings": SSOSettingsBase._fga_mappings_to_dict(settings.fga_mappings),
            },
            "domains": domains,
        }

    @staticmethod
    def _compose_configure_saml_settings_body(
        tenant_id: str,
        settings: SSOSAMLSettings,
        redirect_url: Optional[str],
        domains: Optional[List[str]],
    ) -> dict:
        attr_mapping = None
        if settings.attribute_mapping:
            attr_mapping = SSOSettingsBase._attribute_mapping_to_dict(settings.attribute_mapping)

        return {
            "tenantId": tenant_id,
            "settings": {
                "idpUrl": settings.idp_url,
                "entityId": settings.idp_entity_id,
                "idpCert": settings.idp_cert,
                "idpAdditionalCerts": settings.idp_additional_certs,
                "spACSUrl": settings.sp_acs_url,
                "spEntityId": settings.sp_entity_id,
                "attributeMapping": attr_mapping,
                "roleMappings": SSOSettingsBase._role_mapping_to_dict(settings.role_mappings),
                "defaultSSORoles": settings.default_sso_roles,
                "groupsPriority": settings.groups_priority,
                "fgaMappings": SSOSettingsBase._fga_mappings_to_dict(settings.fga_mappings),
                "configFGATenantIDResourcePrefix": settings.config_fga_tenant_id_resource_prefix,
                "configFGATenantIDResourceSuffix": settings.config_fga_tenant_id_resource_suffix,
            },
            "redirectUrl": redirect_url,
            "domains": domains,
        }

    @staticmethod
    def _compose_configure_saml_settings_by_metadata_body(
        tenant_id: str,
        settings: SSOSAMLSettingsByMetadata,
        redirect_url: Optional[str],
        domains: Optional[List[str]],
    ) -> dict:
        attr_mapping = None
        if settings.attribute_mapping:
            attr_mapping = SSOSettingsBase._attribute_mapping_to_dict(settings.attribute_mapping)

        return {
            "tenantId": tenant_id,
            "settings": {
                "idpMetadataUrl": settings.idp_metadata_url,
                "spACSUrl": settings.sp_acs_url,
                "spEntityId": settings.sp_entity_id,
                "attributeMapping": attr_mapping,
                "roleMappings": SSOSettingsBase._role_mapping_to_dict(settings.role_mappings),
                "defaultSSORoles": settings.default_sso_roles,
                "groupsPriority": settings.groups_priority,
                "fgaMappings": SSOSettingsBase._fga_mappings_to_dict(settings.fga_mappings),
                "configFGATenantIDResourcePrefix": settings.config_fga_tenant_id_resource_prefix,
                "configFGATenantIDResourceSuffix": settings.config_fga_tenant_id_resource_suffix,
            },
            "redirectUrl": redirect_url,
            "domains": domains,
        }
