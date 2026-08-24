from typing import Dict, List, Optional

from descope._http_base import HTTPBase
from descope.management._sso_settings_base import SSOSettingsBase
from descope.management.common import MgmtV1


class RoleMapping:
    """Map IDP group names to the Descope role name"""

    def __init__(self, groups: List[str], role_name: str):
        self.groups = groups
        self.role_name = role_name


class FGAGroupMappingRelation:
    """A single FGA relation that maps an IDP group to an FGA resource/relation."""

    def __init__(self, resource: str, relation_definition: str, namespace: str):
        self.resource = resource
        self.relation_definition = relation_definition
        self.namespace = namespace


class FGAGroupMapping:
    """A list of FGA relations to apply for an IDP group."""

    def __init__(self, relations: Optional[List[FGAGroupMappingRelation]] = None):
        self.relations = relations


class AttributeMapping:
    """Map Descope user attributes to IDP user attributes"""

    def __init__(
        self,
        name: Optional[str] = None,
        email: Optional[str] = None,
        phone_number: Optional[str] = None,
        group: Optional[str] = None,
        given_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        family_name: Optional[str] = None,
        picture: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
    ):
        self.name = name
        self.email = email
        self.phone_number = phone_number
        self.group = group
        self.given_name = given_name
        self.middle_name = middle_name
        self.family_name = family_name
        self.picture = picture
        self.custom_attributes = custom_attributes


class XAAIssuerSettings:
    """
    Cross-App Access (XAA / ID-JAG) trusted-issuer settings, including per-issuer JIT provisioning and
    user attribute mapping (parity with the SSO login JIT). Group-to-role mapping reuses the tenant's
    shared SSO group mapping. Describes the shape of each entry under the trust config's ``issuers`` map,
    as returned by the dedicated Load XAA settings API (``load_xaa_settings`` / ``load_all_xaa_settings``).
    """

    def __init__(
        self,
        jwks_uri: Optional[str] = None,
        sign_algorithm: Optional[str] = None,
        user_info_uri: Optional[str] = None,
        external_id_field_name: Optional[str] = None,
        jit_disabled: Optional[bool] = None,
        attribute_mapping: Optional[AttributeMapping] = None,
    ):
        self.jwks_uri = jwks_uri
        self.sign_algorithm = sign_algorithm
        self.user_info_uri = user_info_uri
        self.external_id_field_name = external_id_field_name
        self.jit_disabled = jit_disabled
        self.attribute_mapping = attribute_mapping


class XAAJWTBearerSettings:
    """
    A tenant's Cross-App Access (XAA / ID-JAG) trust config: the set of trusted issuers keyed by issuer
    URL, plus the jwt-bearer grant configuration. Used as the ``settings`` field of the XAA configure
    request, and returned under ``settings`` by the dedicated Load XAA settings API
    (``load_xaa_settings`` / ``load_all_xaa_settings``).
    """

    def __init__(
        self,
        issuers: Optional[Dict[str, XAAIssuerSettings]] = None,
        jwt_bearer_grant_type_audience_to_use: Optional[str] = None,
        jwt_bearer_grant_type_scope_to_use: Optional[str] = None,
        jwt_bearer_grant_type_custom_claims_to_use: Optional[str] = None,
    ):
        self.issuers = issuers
        self.jwt_bearer_grant_type_audience_to_use = jwt_bearer_grant_type_audience_to_use
        self.jwt_bearer_grant_type_scope_to_use = jwt_bearer_grant_type_scope_to_use
        self.jwt_bearer_grant_type_custom_claims_to_use = jwt_bearer_grant_type_custom_claims_to_use


class XAASettings:
    """
    Cross-App Access (XAA / ID-JAG) write payload for a single SSO configuration of a tenant.

    ``settings`` holds the trusted issuers (keyed by issuer URL) and jwt-bearer grant configuration; the
    remaining fields are the config-level shared group/role mapping, which is shared across
    SAML / OIDC / SCIM / XAA for the sso_id (NOT a per-issuer mapping). Role references are by name and
    resolved to role ids server-side; these reuse the same types the SSO SAML settings use.
    """

    def __init__(
        self,
        enabled: Optional[bool] = None,
        settings: Optional[XAAJWTBearerSettings] = None,
        role_mappings: Optional[List[RoleMapping]] = None,
        default_sso_roles: Optional[List[str]] = None,
        fga_mappings: Optional[Dict[str, FGAGroupMapping]] = None,  # map of IDP group name -> FGA relations
        groups_priority: Optional[List[str]] = None,  # list of group names in priority order (first = highest priority)
        group_priority_enabled: Optional[bool] = None,
        allow_override_roles: Optional[bool] = None,
        provider_id: Optional[str] = None,  # selected IdP provider template id (mirrors SSO SAML providerID)
    ):
        self.enabled = enabled
        self.settings = settings
        self.role_mappings = role_mappings
        self.default_sso_roles = default_sso_roles
        self.fga_mappings = fga_mappings
        self.groups_priority = groups_priority
        self.group_priority_enabled = group_priority_enabled
        self.allow_override_roles = allow_override_roles
        self.provider_id = provider_id


class OIDCAttributeMapping:
    """
    Represents tenant OIDC attribute mapping.
    """

    def __init__(
        self,
        login_id: str,
        name: str,
        given_name: str,
        middle_name: str,
        family_name: str,
        email: str,
        verified_email: str,
        username: str,
        phone_number: str,
        verified_phone: str,
        picture: str,
    ):
        self.login_id = login_id
        self.name = name
        self.given_name = given_name
        self.middle_name = middle_name
        self.family_name = family_name
        self.email = email
        self.verified_email = verified_email
        self.username = username
        self.phone_number = phone_number
        self.verified_phone = verified_phone
        self.picture = picture


class SSOOIDCSettings:
    """
    Represents tenant OIDC settings.
    """

    def __init__(
        self,
        name: str,
        client_id: str,
        client_secret: Optional[str] = None,
        redirect_url: Optional[str] = None,
        auth_url: Optional[str] = None,
        token_url: Optional[str] = None,
        user_data_url: Optional[str] = None,
        scope: Optional[List[str]] = None,
        jwks_url: Optional[str] = None,
        attribute_mapping: Optional[OIDCAttributeMapping] = None,
        manage_provider_tokens: Optional[bool] = False,
        callback_domain: Optional[str] = None,
        prompt: Optional[List[str]] = None,
        grant_type: Optional[str] = None,
        issuer: Optional[str] = None,
        groups_priority: Optional[List[str]] = None,  # list of group names in priority order (first = highest priority)
        fga_mappings: Optional[Dict[str, FGAGroupMapping]] = None,  # map of IDP group name -> FGA relations
    ):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_url = redirect_url
        self.auth_url = auth_url
        self.token_url = token_url
        self.user_data_url = user_data_url
        self.scope = scope
        self.jwks_url = jwks_url
        self.attribute_mapping = attribute_mapping
        self.manage_provider_tokens = manage_provider_tokens
        self.callback_domain = callback_domain
        self.prompt = prompt
        self.grant_type = grant_type
        self.issuer = issuer
        self.groups_priority = groups_priority
        self.fga_mappings = fga_mappings


class SSOSAMLSettings:
    """
    Represents tenant SAML settings (manually configuration).
    """

    def __init__(
        self,
        idp_url: str,
        idp_entity_id: str,
        idp_cert: str,
        attribute_mapping: Optional[AttributeMapping] = None,
        role_mappings: Optional[List[RoleMapping]] = None,
        default_sso_roles: Optional[List[str]] = None,
        idp_additional_certs: Optional[List[str]] = None,
        groups_priority: Optional[List[str]] = None,  # list of group names in priority order (first = highest priority)
        fga_mappings: Optional[Dict[str, FGAGroupMapping]] = None,  # map of IDP group name -> FGA relations
        config_fga_tenant_id_resource_prefix: Optional[str] = None,
        config_fga_tenant_id_resource_suffix: Optional[str] = None,
        # NOTICE - the following fields should be overridden only in case of SSO migration, otherwise, do not modify these fields
        sp_acs_url: Optional[str] = None,
        sp_entity_id: Optional[str] = None,
    ):
        self.idp_url = idp_url
        self.idp_entity_id = idp_entity_id
        self.idp_cert = idp_cert
        self.attribute_mapping = attribute_mapping
        self.role_mappings = role_mappings
        self.default_sso_roles = default_sso_roles
        self.idp_additional_certs = idp_additional_certs
        self.sp_acs_url = sp_acs_url
        self.sp_entity_id = sp_entity_id
        self.groups_priority = groups_priority
        self.fga_mappings = fga_mappings
        self.config_fga_tenant_id_resource_prefix = config_fga_tenant_id_resource_prefix
        self.config_fga_tenant_id_resource_suffix = config_fga_tenant_id_resource_suffix


class SSOSAMLSettingsByMetadata:
    """
    Represents tenant SAML settings (automatically (by metadata xml) configuration).
    """

    def __init__(
        self,
        idp_metadata_url: str,
        attribute_mapping: Optional[AttributeMapping] = None,
        role_mappings: Optional[List[RoleMapping]] = None,
        default_sso_roles: Optional[List[str]] = None,
        groups_priority: Optional[List[str]] = None,  # list of group names in priority order (first = highest priority)
        fga_mappings: Optional[Dict[str, FGAGroupMapping]] = None,  # map of IDP group name -> FGA relations
        config_fga_tenant_id_resource_prefix: Optional[str] = None,
        config_fga_tenant_id_resource_suffix: Optional[str] = None,
        # NOTICE - the following fields should be overridden only in case of SSO migration, otherwise, do not modify these fields
        sp_acs_url: Optional[str] = None,
        sp_entity_id: Optional[str] = None,
        # IdP entity ID - set so IdP-initiated login can resolve the tenant by the SAML response issuer.
        # Appended last to preserve positional compatibility for existing callers.
        idp_entity_id: Optional[str] = None,
    ):
        self.idp_metadata_url = idp_metadata_url
        self.idp_entity_id = idp_entity_id
        self.attribute_mapping = attribute_mapping
        self.role_mappings = role_mappings
        self.default_sso_roles = default_sso_roles
        self.sp_acs_url = sp_acs_url
        self.sp_entity_id = sp_entity_id
        self.groups_priority = groups_priority
        self.fga_mappings = fga_mappings
        self.config_fga_tenant_id_resource_prefix = config_fga_tenant_id_resource_prefix
        self.config_fga_tenant_id_resource_suffix = config_fga_tenant_id_resource_suffix


class SSOSettings(SSOSettingsBase, HTTPBase):
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
             {"tenant": {"id": "T2AAAA", "name": "myTenantName", "selfProvisioningDomains": [], "customAttributes": {}, "authType": "saml", "domains": ["lulu", "kuku"]}, "saml": {"idpEntityId": "", "idpSSOUrl": "", "idpCertificate": "", "idpAdditionalCertificates": [], "idpMetadataUrl": "https://dummy.com/metadata", "spEntityId": "", "spACSUrl": "", "spCertificate": "", "attributeMapping": {"name": "name", "email": "email", "username": "", "phoneNumber": "phone", "group": "", "givenName": "", "middleName": "", "familyName": "", "picture": "", "customAttributes": {}}, "groupsMapping": [], "redirectUrl": "", "lastSuccessTestTime": 0}, "oidc": {"name": "", "clientId": "", "clientSecret": "", "redirectUrl": "", "authUrl": "", "tokenUrl": "", "userDataUrl": "", "scope": [], "JWKsUrl": "", "userAttrMapping": {"loginId": "sub", "username": "", "name": "name", "email": "email", "phoneNumber": "phone_number", "verifiedEmail": "email_verified", "verifiedPhone": "phone_number_verified", "picture": "picture", "givenName": "given_name", "middleName": "middle_name", "familyName": "family_name"}, "manageProviderTokens": False, "callbackDomain": "", "prompt": [], "grantType": "authorization_code", "issuer": "", "lastSuccessTestTime": 0}}

        The "lastSuccessTestTime" field (epoch seconds, read-only) reports the last successful SSO test login on the configuration; a non-zero value means the configuration was tested successfully.

        Raise:
        AuthException: raised if load configuration operation fails
        """
        response = self._http.get(
            uri=MgmtV1.sso_load_settings_path,
            params={"tenantId": tenant_id},
        )
        return response.json()

    def recalculate_sso_mappings(
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

        self._http.post(
            uri=MgmtV1.sso_recalculate_mappings_path,
            body=body,
        )

    def configure_sso_redirect_url(
        self,
        tenant_id: str,
        saml_redirect_url: Optional[str] = None,
        oauth_redirect_url: Optional[str] = None,
        sso_id: Optional[str] = None,
    ):
        """
        Configure SSO redirect URLs for a tenant.
        This will override the existing redirect URLs for the tenant and will not affect any other SSO setting.

        Args:
        tenant_id (str): The tenant ID to be configured
        saml_redirect_url (str): Optional SAML redirect URL
        oauth_redirect_url (str): Optional OAuth redirect URL
        sso_id (str): Optional SSO identifier for multi-SSO configurations

        Raise:
        AuthException: raised if configuration operation fails
        """
        body = {"tenantId": tenant_id}
        if saml_redirect_url is not None:
            body["samlRedirectUrl"] = saml_redirect_url
        if oauth_redirect_url is not None:
            body["oauthRedirectUrl"] = oauth_redirect_url
        if sso_id:
            body["ssoId"] = sso_id

        self._http.post(
            uri=MgmtV1.sso_redirect_path,
            body=body,
        )

    def load_all_settings(
        self,
        tenant_id: str,
    ) -> dict:
        """
        Load all SSO settings for the provided tenant_id (for multi-SSO usage).

        Args:
        tenant_id (str): The tenant ID of the desired SSO Settings

        Return value (dict):
        Containing all loaded SSO settings information.

        Raise:
        AuthException: raised if load configuration operation fails
        """
        response = self._http.get(
            uri=MgmtV1.sso_load_all_settings_path,
            params={"tenantId": tenant_id},
        )
        return response.json()

    def new_settings(
        self,
        tenant_id: str,
        display_name: str,
        sso_id: Optional[str] = None,
    ) -> dict:
        """
        Create new SSO settings for a tenant.

        Args:
        tenant_id (str): The tenant ID to create settings for
        display_name (str): Display name for the SSO settings
        sso_id (str): Optional SSO identifier

        Return value (dict):
        Containing the created SSO settings information.

        Raise:
        AuthException: raised if creation operation fails
        """
        body = {
            "tenantId": tenant_id,
            "displayName": display_name,
        }
        if sso_id:
            body["ssoId"] = sso_id

        response = self._http.post(
            uri=MgmtV1.sso_new_settings_path,
            body=body,
        )
        return response.json()

    def delete_settings(
        self,
        tenant_id: str,
        sso_id: Optional[str] = None,
    ):
        """
        Delete SSO setting for the provided tenant_id.

        Args:
        tenant_id (str): The tenant ID of the desired SSO Settings to delete
        sso_id (str): Optional, the SSO configuration id (for multi-SSO). Omit for the default SSO configuration.

        Raise:
        AuthException: raised if delete operation fails
        """
        params = {"tenantId": tenant_id}
        if sso_id:
            params["ssoId"] = sso_id

        self._http.delete(
            MgmtV1.sso_settings_path,
            params=params,
        )

    def configure_auth_type(
        self,
        tenant_id: str,
        auth_type: str,
        sso_id: Optional[str] = None,
    ):
        """
        Set the authentication type of a single SSO configuration, leaving its stored SAML/OIDC
        settings, mappings and domains untouched.

        Args:
        tenant_id (str): The tenant ID the configuration belongs to
        auth_type (str): "none" disables the configuration without deleting it, "saml" or "oidc"
            enable it on that protocol with its stored settings, so re-enabling needs no payload.
        sso_id (str): Optional, the SSO configuration id (for multi-SSO). Omit for the default SSO configuration.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._http.post(
            MgmtV1.sso_configure_auth_type_path,
            body=SSOSettings._compose_configure_auth_type_body(tenant_id, auth_type, sso_id),
        )

    def configure_oidc_settings(
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

        self._http.post(
            MgmtV1.sso_configure_oidc_settings,
            body=SSOSettings._compose_configure_oidc_settings_body(tenant_id, settings, domains),
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

        self._http.post(
            MgmtV1.sso_configure_saml_settings,
            body=SSOSettings._compose_configure_saml_settings_body(tenant_id, settings, redirect_url, domains),
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

        self._http.post(
            MgmtV1.sso_configure_saml_by_metadata_settings,
            body=SSOSettings._compose_configure_saml_settings_by_metadata_body(
                tenant_id, settings, redirect_url, domains
            ),
        )

    def configure_xaa_settings(
        self,
        tenant_id: str,
        settings: XAASettings,
        sso_id: Optional[str] = None,
    ):
        """
        Configure Cross-App Access (XAA / ID-JAG) trust settings for a single SSO configuration of a tenant.

        Args:
        tenant_id (str): The tenant ID to be configured
        settings (XAASettings): The trusted issuers + grant configuration together with the config-level
            shared group/role mapping. The shared mapping is shared across SAML / OIDC / SCIM / XAA for the sso_id.
        sso_id (str): Optional, the SSO configuration id (for multi-SSO). Omit for the default SSO configuration.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._http.post(
            MgmtV1.sso_configure_xaa_settings,
            body=SSOSettings._compose_configure_xaa_settings_body(tenant_id, settings, sso_id),
        )

    def load_xaa_settings(
        self,
        tenant_id: str,
        sso_id: Optional[str] = None,
    ) -> dict:
        """
        Load the Cross-App Access (XAA / ID-JAG) trust settings for a single SSO configuration of a tenant.

        Args:
        tenant_id (str): The tenant ID of the desired XAA settings
        sso_id (str): Optional, the SSO configuration id (for multi-SSO). Omit for the default SSO configuration.

        Return value (dict):
        Containing the loaded XAA settings (ssoId, enabled, settings, groupsMapping, defaultSSORoles,
        fgaMappings, groupsPriority, groupPriorityEnabled, allowOverrideRoles).

        Raise:
        AuthException: raised if load operation fails
        """
        params = {"tenantId": tenant_id}
        if sso_id:
            params["ssoId"] = sso_id
        response = self._http.get(
            uri=MgmtV1.sso_configure_xaa_settings,
            params=params,
        )
        return response.json()

    def load_all_xaa_settings(
        self,
        tenant_id: str,
    ) -> dict:
        """
        Load the Cross-App Access (XAA / ID-JAG) trust settings for every SSO configuration of a tenant.

        Args:
        tenant_id (str): The tenant ID of the desired XAA settings

        Return value (dict):
        Containing all loaded XAA settings under the ``XAASettings`` key.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(
            uri=MgmtV1.sso_load_all_xaa_settings,
            params={"tenantId": tenant_id},
        )
        return response.json()

    def delete_xaa_settings(
        self,
        tenant_id: str,
        sso_id: Optional[str] = None,
    ):
        """
        Delete the Cross-App Access (XAA / ID-JAG) trust settings of a single SSO configuration of a tenant.

        Args:
        tenant_id (str): The tenant ID of the desired XAA settings to delete
        sso_id (str): Optional, the SSO configuration id (for multi-SSO). Omit for the default SSO configuration.

        Raise:
        AuthException: raised if delete operation fails
        """
        params = {"tenantId": tenant_id}
        if sso_id:
            params["ssoId"] = sso_id
        self._http.delete(
            MgmtV1.sso_configure_xaa_settings,
            params=params,
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
        response = self._http.get(
            uri=MgmtV1.sso_settings_path,
            params={"tenantId": tenant_id},
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
        self._http.post(
            MgmtV1.sso_settings_path,
            body=SSOSettings._compose_configure_body(tenant_id, idp_url, entity_id, idp_cert, redirect_url, domains),
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
        self._http.post(
            MgmtV1.sso_metadata_path,
            body=SSOSettings._compose_metadata_body(tenant_id, idp_metadata_url, redirect_url, domains),
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
        self._http.post(
            MgmtV1.sso_mapping_path,
            body=SSOSettings._compose_mapping_body(tenant_id, role_mappings, attribute_mapping),
        )
