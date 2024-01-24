from typing import List, Optional

from descope._auth_base import AuthBase
from descope.management.common import (
    MgmtV1,
    SSOOIDCSettings,
    SSOSAMLSettings,
    SSOSAMLSettingsByMetadata,
)


class RoleMapping:
    """Map IDP group names to the Descope role name"""

    def __init__(self, groups: List[str], role_name: str):
        self.groups = groups
        self.role_name = role_name


class AttributeMapping:
    """Map Descope user attributes to IDP user attributes"""

    def __init__(
        self,
        name: Optional[str] = None,
        email: Optional[str] = None,
        phone_number: Optional[str] = None,
        group: Optional[str] = None,
    ):
        self.name = name
        self.email = email
        self.phone_number = phone_number
        self.group = group


class SSOSettings(AuthBase):
    def load_settings(
        self,
        tenant_id: str,
    ) -> dict:
        """
        Load SSO setting for the provided tenant_id.

        Args:
        tenant_id (str): The tenant ID of the desired SSO Settings

        Return value (dict):
        Containing the loaded SSO settings information.
        Return dict in the format:
             {"tenant": {"id": "T2AAAA", "name": "myTenantName", "selfProvisioningDomains": [], "customAttributes": {}, "authType": "saml", "domains": ["lulu", "kuku"]}, "saml": {"idpEntityId": "", "idpSSOUrl": "", "idpCertificate": "", "idpMetadataUrl": "https://dummy.com/metadata", "spEntityId": "", "spACSUrl": "", "spCertificate": "", "attributeMapping": {"name": "name", "email": "email", "username": "", "phoneNumber": "phone", "group": "", "givenName": "", "middleName": "", "familyName": "", "picture": "", "customAttributes": {}}, "groupsMapping": [], "redirectUrl": ""}, "oidc": {"name": "", "clientId": "", "clientSecret": "", "redirectUrl": "", "authUrl": "", "tokenUrl": "", "userDataUrl": "", "scope": [], "JWKsUrl": "", "userAttrMapping": {"loginId": "sub", "username": "", "name": "name", "email": "email", "phoneNumber": "phone_number", "verifiedEmail": "email_verified", "verifiedPhone": "phone_number_verified", "picture": "picture", "givenName": "given_name", "middleName": "middle_name", "familyName": "family_name"}, "manageProviderTokens": False, "callbackDomain": "", "prompt": [], "grantType": "authorization_code", "issuer": ""}}

        Raise:
        AuthException: raised if load configuration operation fails
        """
        response = self._auth.do_get(
            uri=MgmtV1.sso_load_settings_path,
            params={"tenantId": tenant_id},
            pswd=self._auth.management_key,
        )
        return response.json()

    def delete_settings(
        self,
        tenant_id: str,
    ):
        """
        Delete SSO setting for the provided tenant_id.

        Args:
        tenant_id (str): The tenant ID of the desired SSO Settings to delete

        Raise:
        AuthException: raised if delete operation fails
        """
        self._auth.do_delete(
            MgmtV1.sso_settings_path,
            {"tenantId": tenant_id},
            pswd=self._auth.management_key,
        )

    def configure_oidc_settings(
        self,
        tenant_id: str,
        settings: SSOOIDCSettings,
        redirect_url: Optional[str] = None,
        domains: Optional[List[str]] = None,
    ):
        """
        Configure SSO OIDC settings for a tenant.

        Args:
        tenant_id (str): The tenant ID to be configured
        settings (SSOOIDCSettings): The OIDC settings to be configured for this tenant (all settings parameters are required).
        redirect_url (str): Optional, the Redirect URL to use after successful authentication, or empty string to reset it (if not given it has to be set when starting an SSO authentication via the request).
        domains (List[str]): Optional,domains used to associate users authenticating via SSO with this tenant. Use empty list or None to reset them.

        Raise:
        AuthException: raised if configuration operation fails
        """

        self._auth.do_post(
            MgmtV1.sso_configure_oidc_settings,
            SSOSettings._compose_configure_oidc_settings_body(
                tenant_id, settings, redirect_url, domains
            ),
            pswd=self._auth.management_key,
        )

    def configure_saml_settings(
        self,
        tenant_id: str,
        settings: SSOSAMLSettings,
        redirect_url: Optional[str] = None,
        domains: Optional[List[str]] = None,
    ):
        """
        Configure SSO SAML settings for a tenant.

        Args:
        tenant_id (str): The tenant ID to be configured
        settings (SSOSAMLSettings): The SAML settings to be configured for this tenant (all settings parameters are required).
        redirect_url (str): Optional,the Redirect URL to use after successful authentication, or empty string to reset it (if not given it has to be set when starting an SSO authentication via the request).
        domains (List[str]): Optional, domains used to associate users authenticating via SSO with this tenant. Use empty list or None to reset them.

        Raise:
        AuthException: raised if configuration operation fails
        """

        self._auth.do_post(
            MgmtV1.sso_configure_saml_settings,
            SSOSettings._compose_configure_saml_settings_body(
                tenant_id, settings, redirect_url, domains
            ),
            pswd=self._auth.management_key,
        )

    def configure_saml_settings_by_metadata(
        self,
        tenant_id: str,
        settings: SSOSAMLSettingsByMetadata,
        redirect_url: Optional[str] = None,
        domains: Optional[List[str]] = None,
    ):
        """
        Configure SSO SAML settings for a tenant by fetching them from an IDP metadata URL.

        Args:
        tenant_id (str): The tenant ID to be configured
        settings (SSOSAMLSettingsByMetadata): The SAML settings to be configured for this tenant (all settings parameters are required).
        redirect_url (str): Optional, the Redirect URL to use after successful authentication, or empty string to reset it (if not given it has to be set when starting an SSO authentication via the request).
        domains (List[str]): Optional, domains used to associate users authenticating via SSO with this tenant. Use empty list or None to reset them.

        Raise:
        AuthException: raised if configuration operation fails
        """

        self._auth.do_post(
            MgmtV1.sso_configure_saml_by_metadata_settings,
            SSOSettings._compose_configure_saml_settings_by_metadata_body(
                tenant_id, settings, redirect_url, domains
            ),
            pswd=self._auth.management_key,
        )

    # DEPRECATED
    def get_settings(
        self,
        tenant_id: str,
    ) -> dict:
        """
        DEPRECATED (use load_settings(..) function instead)

        Get SSO setting for the provided tenant_id.

        Args:
        tenant_id (str): The tenant ID of the desired SSO Settings

        Return value (dict):
        Containing the loaded SSO settings information.

        Raise:
        AuthException: raised if configuration operation fails
        """
        response = self._auth.do_get(
            uri=MgmtV1.sso_settings_path,
            params={"tenantId": tenant_id},
            pswd=self._auth.management_key,
        )
        return response.json()

    # DEPRECATED
    def configure(
        self,
        tenant_id: str,
        idp_url: str,
        entity_id: str,
        idp_cert: str,
        redirect_url: str,
        domains: Optional[List[str]] = None,
    ) -> None:
        """
        DEPRECATED (use configure_saml_settings(..) function instead)

        Configure SSO setting for a tenant manually. Alternatively, `configure_via_metadata` can be used instead.

        Args:
        tenant_id (str): The tenant ID to be configured
        idp_url (str): The URL for the identity provider.
        entity_id (str): The entity ID (in the IDP).
        idp_cert (str): The certificate provided by the IDP.
        redirect_url (str): The Redirect URL to use after successful authentication, or empty string to reset it.
        domain (List[str]): domains used to associate users authenticating via SSO with this tenant. Use empty list or None to reset them.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._auth.do_post(
            MgmtV1.sso_settings_path,
            SSOSettings._compose_configure_body(
                tenant_id, idp_url, entity_id, idp_cert, redirect_url, domains
            ),
            pswd=self._auth.management_key,
        )

    # DEPRECATED
    def configure_via_metadata(
        self,
        tenant_id: str,
        idp_metadata_url: str,
        redirect_url: Optional[str] = None,
        domains: Optional[List[str]] = None,
    ):
        """
        DEPRECATED (use configure_saml_settings_by_metadata(..) function instead)

        Configure SSO setting for am IDP metadata URL. Alternatively, `configure` can be used instead.

        Args:
        tenant_id (str): The tenant ID to be configured
        idp_metadata_url (str): The URL to fetch SSO settings from.
        redirect_url (str): The Redirect URL to use after successful authentication, or empty string to reset it.
        domains (List[str]): domains used to associate users authenticating via SSO with this tenant. Use empty list or None to reset them.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._auth.do_post(
            MgmtV1.sso_metadata_path,
            SSOSettings._compose_metadata_body(
                tenant_id, idp_metadata_url, redirect_url, domains
            ),
            pswd=self._auth.management_key,
        )

    # DEPRECATED
    def mapping(
        self,
        tenant_id: str,
        role_mappings: Optional[List[RoleMapping]] = None,
        attribute_mapping: Optional[AttributeMapping] = None,
    ):
        """
        DEPRECATED (use configure_saml_settings(..) or configure_saml_settings_by_metadata(..) functions instead)

        Configure SSO role mapping from the IDP groups to the Descope roles.

        Args:
        tenant_id (str): The tenant ID to be configured
        role_mappings (List[RoleMapping]): A mapping between IDP groups and Descope roles.
        attribute_mapping (AttributeMapping): A mapping between IDP user attributes and descope attributes.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._auth.do_post(
            MgmtV1.sso_mapping_path,
            SSOSettings._compose_mapping_body(
                tenant_id, role_mappings, attribute_mapping
            ),
            pswd=self._auth.management_key,
        )

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
            "roleMappings": SSOSettings._role_mapping_to_dict(role_mapping),
            "attributeMapping": SSOSettings._attribute_mapping_to_dict(
                attribute_mapping
            ),
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
        }

    @staticmethod
    def _compose_configure_oidc_settings_body(
        tenant_id: str,
        settings: SSOOIDCSettings,
        redirect_url: str,
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
            },
            "redirectUrl": redirect_url,
            "domains": domains,
        }

    @staticmethod
    def _compose_configure_saml_settings_body(
        tenant_id: str,
        settings: SSOSAMLSettings,
        redirect_url: str,
        domains: Optional[List[str]],
    ) -> dict:
        attr_mapping = None
        if settings.attribute_mapping:
            attr_mapping = {
                "name": settings.attribute_mapping.name,
                "givenName": settings.attribute_mapping.given_name,
                "middleName": settings.attribute_mapping.middle_name,
                "familyName": settings.attribute_mapping.family_name,
                "picture": settings.attribute_mapping.picture,
                "email": settings.attribute_mapping.email,
                "phoneNumber": settings.attribute_mapping.phone_number,
                "group": settings.attribute_mapping.group,
                "customAttributes": settings.attribute_mapping.custom_attributes,
            }

        grp_mapping = None
        if settings.role_mappings:
            grp_mapping = []
            for grp in settings.role_mappings:
                grp_mapping.append({"groups": grp.groups, "roleName": grp.role})

        return {
            "tenantId": tenant_id,
            "settings": {
                "idpUrl": settings.idp_url,
                "entityId": settings.idp_entity_id,
                "idpCert": settings.idp_cert,
                "attributeMapping": attr_mapping,
                "roleMappings": grp_mapping,
            },
            "redirectUrl": redirect_url,
            "domains": domains,
        }

    @staticmethod
    def _compose_configure_saml_settings_by_metadata_body(
        tenant_id: str,
        settings: SSOSAMLSettingsByMetadata,
        redirect_url: str,
        domains: Optional[List[str]],
    ) -> dict:
        attr_mapping = None
        if settings.attribute_mapping:
            attr_mapping = {
                "name": settings.attribute_mapping.name,
                "givenName": settings.attribute_mapping.given_name,
                "middleName": settings.attribute_mapping.middle_name,
                "familyName": settings.attribute_mapping.family_name,
                "picture": settings.attribute_mapping.picture,
                "email": settings.attribute_mapping.email,
                "phoneNumber": settings.attribute_mapping.phone_number,
                "group": settings.attribute_mapping.group,
                "customAttributes": settings.attribute_mapping.custom_attributes,
            }

        grp_mapping = None
        if settings.role_mappings:
            grp_mapping = []
            for grp in settings.role_mappings:
                grp_mapping.append({"groups": grp.groups, "roleName": grp.role})

        return {
            "tenantId": tenant_id,
            "settings": {
                "idpMetadataUrl": settings.idp_metadata_url,
                "attributeMapping": attr_mapping,
                "roleMappings": grp_mapping,
            },
            "redirectUrl": redirect_url,
            "domains": domains,
        }
