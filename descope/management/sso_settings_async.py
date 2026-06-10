from __future__ import annotations

from typing import List, Optional

from descope._http_base import AsyncHTTPBase
from descope.management._sso_settings_base import SSOSettingsBase
from descope.management.common import MgmtV1
from descope.management.sso_settings import (
    AttributeMapping,
    RoleMapping,
    SSOOIDCSettings,
    SSOSAMLSettings,
    SSOSAMLSettingsByMetadata,
)


class SSOSettingsAsync(SSOSettingsBase, AsyncHTTPBase):
    """Async counterpart of SSOSettings — all HTTP calls are coroutines."""

    async def load_settings(
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
             {"tenant": {"id": "T2AAAA", "name": "myTenantName", "selfProvisioningDomains": [], "customAttributes": {}, "authType": "saml", "domains": ["lulu", "kuku"]}, "saml": {"idpEntityId": "", "idpSSOUrl": "", "idpCertificate": "", "idpAdditionalCertificates": [], "idpMetadataUrl": "https://dummy.com/metadata", "spEntityId": "", "spACSUrl": "", "spCertificate": "", "attributeMapping": {"name": "name", "email": "email", "username": "", "phoneNumber": "phone", "group": "", "givenName": "", "middleName": "", "familyName": "", "picture": "", "customAttributes": {}}, "groupsMapping": [], "redirectUrl": ""}, "oidc": {"name": "", "clientId": "", "clientSecret": "", "redirectUrl": "", "authUrl": "", "tokenUrl": "", "userDataUrl": "", "scope": [], "JWKsUrl": "", "userAttrMapping": {"loginId": "sub", "username": "", "name": "name", "email": "email", "phoneNumber": "phone_number", "verifiedEmail": "email_verified", "verifiedPhone": "phone_number_verified", "picture": "picture", "givenName": "given_name", "middleName": "middle_name", "familyName": "family_name"}, "manageProviderTokens": False, "callbackDomain": "", "prompt": [], "grantType": "authorization_code", "issuer": ""}}

        Raise:
        AuthException: raised if load configuration operation fails
        """
        response = await self._http.get(
            uri=MgmtV1.sso_load_settings_path,
            params={"tenantId": tenant_id},
        )
        return response.json()

    async def recalculate_sso_mappings(
        self,
        tenant_id: str,
        sso_id: Optional[str] = None,
    ):
        """
        Recalculate SSO group to role mappings for all users in a tenant.

        This method triggers a recalculation of user roles based on the current SSO group mappings.
        It will update the roles for all users in the tenant who have SSO group mappings.

        Args:
        tenant_id (str): The tenant ID (required)
        sso_id (str): Optional, specify to recalculate mappings for a specific SSO configuration

        Raise:
        AuthException: raised if recalculation operation fails
        """
        body = {"tenantId": tenant_id}
        if sso_id:
            body["ssoId"] = sso_id

        await self._http.post(
            uri=MgmtV1.sso_recalculate_mappings_path,
            body=body,
        )

    async def delete_settings(
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
        await self._http.delete(
            MgmtV1.sso_settings_path,
            params={"tenantId": tenant_id},
        )

    async def configure_oidc_settings(
        self,
        tenant_id: str,
        settings: SSOOIDCSettings,
        domains: Optional[List[str]] = None,
    ):
        """
        Configure SSO OIDC settings for a tenant.

        Args:
        tenant_id (str): The tenant ID to be configured
        settings (SSOOIDCSettings): The OIDC settings to be configured for this tenant (all settings parameters are required).
        domains (List[str]): Optional,domains used to associate users authenticating via SSO with this tenant. Use empty list or None to reset them.

        Raise:
        AuthException: raised if configuration operation fails
        """

        await self._http.post(
            MgmtV1.sso_configure_oidc_settings,
            body=SSOSettingsAsync._compose_configure_oidc_settings_body(tenant_id, settings, domains),
        )

    async def configure_saml_settings(
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

        await self._http.post(
            MgmtV1.sso_configure_saml_settings,
            body=SSOSettingsAsync._compose_configure_saml_settings_body(tenant_id, settings, redirect_url, domains),
        )

    async def configure_saml_settings_by_metadata(
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

        await self._http.post(
            MgmtV1.sso_configure_saml_by_metadata_settings,
            body=SSOSettingsAsync._compose_configure_saml_settings_by_metadata_body(
                tenant_id, settings, redirect_url, domains
            ),
        )

    # DEPRECATED
    async def get_settings(
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
        response = await self._http.get(
            uri=MgmtV1.sso_settings_path,
            params={"tenantId": tenant_id},
        )
        return response.json()

    # DEPRECATED
    async def configure(
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
        await self._http.post(
            MgmtV1.sso_settings_path,
            body=SSOSettingsAsync._compose_configure_body(tenant_id, idp_url, entity_id, idp_cert, redirect_url, domains),
        )

    # DEPRECATED
    async def configure_via_metadata(
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
        await self._http.post(
            MgmtV1.sso_metadata_path,
            body=SSOSettingsAsync._compose_metadata_body(tenant_id, idp_metadata_url, redirect_url, domains),
        )

    # DEPRECATED
    async def mapping(
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
        await self._http.post(
            MgmtV1.sso_mapping_path,
            body=SSOSettingsAsync._compose_mapping_body(tenant_id, role_mappings, attribute_mapping),
        )

