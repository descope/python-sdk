from __future__ import annotations

from typing import Any, List, Optional

from descope._http_base import HTTPBase
from descope.management.common import (
    MgmtV1,
    SAMLIDPAttributeMappingInfo,
    SAMLIDPGroupsMappingInfo,
    saml_idp_attribute_mapping_info_to_dict,
    saml_idp_groups_mapping_info_to_dict,
)


class SSOApplication(HTTPBase):
    def create_oidc_application(
        self,
        name: str,
        login_page_url: str,
        id: Optional[str] = None,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        enabled: Optional[bool] = True,
        force_authentication: Optional[bool] = False,
    ) -> dict:
        """
        Create a new OIDC sso application with the given name. SSO application IDs are provisioned automatically, but can be provided
        explicitly if needed. Both the name and ID must be unique per project.

        Args:
        name (str): The sso application's name.
        login_page_url (str): The URL where login page is hosted.
        id (str): Optional sso application ID.
        description (str): Optional sso application description.
        logo (str): Optional sso application logo.
        enabled (bool): Optional (default True) does the sso application will be enabled or disabled.
        force_authentication (bool): Optional determine if the IdP should force the user to re-authenticate.

        Return value (dict):
        Return dict in the format
             {"id": <id>}

        Raise:
        AuthException: raised if create operation fails
        """
        uri = MgmtV1.sso_application_oidc_create_path
        response = self._http.post(
            uri,
            body=SSOApplication._compose_create_update_oidc_body(
                name,
                login_page_url,
                id,
                description,
                logo,
                enabled,
                force_authentication,
            ),
        )
        return response.json()

    def create_saml_application(
        self,
        name: str,
        login_page_url: str,
        id: Optional[str] = None,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        enabled: Optional[bool] = True,
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
    ) -> dict:
        """
        Create a new SAML sso application with the given name. SSO application IDs are provisioned automatically, but can be provided
        explicitly if needed. Both the name and ID must be unique per project.

        Args:
        name (str): The sso application's name.
        login_page_url (str): The URL where login page is hosted.
        id (str): Optional sso application ID.
        description (str): Optional sso application description.
        logo (str): Optional sso application logo.
        enabled (bool): Optional set the sso application as enabled or disabled.
        use_metadata_info (bool): Optional determine if SP info should be automatically fetched from metadata_url or by specified it by the entity_id, acs_url, certificate parameters.
        metadata_url (str): Optional SP metadata url which include all the SP SAML info.
        entity_id (str): Optional SP entity id.
        acs_url (str): Optional SP ACS (saml callback) url.
        certificate (str): Optional SP certificate, relevant only when SAML request must be signed.
        attribute_mapping (List[SAMLIDPAttributeMappingInfo]): Optional list of Descope (IdP) attributes to SP mapping.
        groups_mapping (List[SAMLIDPGroupsMappingInfo]): Optional list of Descope (IdP) roles that will be mapped to SP groups.
        acs_allowed_callbacks (List[str]): Optional list of urls wildcards strings represents the allowed ACS urls that will be accepted while arriving on the SAML request as SP callback urls.
        subject_name_id_type (str): Optional define the SAML Assertion subject name type, leave empty for using Descope user-id or set to "email"/"phone".
        subject_name_id_format (str): Optional define the SAML Assertion subject name format, leave empty for using "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".
        default_relay_state (str): Optional define the default relay state.
        force_authentication (bool): Optional determine if the IdP should force the user to re-authenticate.
        logout_redirect_url (str): Optional Target URL to which the user will be redirected upon logout completion.

        Return value (dict):
        Return dict in the format
             {"id": <id>}

        Raise:
        AuthException: raised if create operation fails
        """

        if use_metadata_info:
            if not metadata_url:
                raise Exception("metadata_url argument must be set")
        else:
            if not entity_id or not acs_url or not certificate:
                raise Exception("entity_id, acs_url, certificate arguments must be set")

        attribute_mapping = [] if attribute_mapping is None else attribute_mapping

        groups_mapping = [] if groups_mapping is None else groups_mapping

        acs_allowed_callbacks = (
            [] if acs_allowed_callbacks is None else acs_allowed_callbacks
        )

        uri = MgmtV1.sso_application_saml_create_path
        response = self._http.post(
            uri,
            body=SSOApplication._compose_create_update_saml_body(
                name,
                login_page_url,
                id,
                description,
                enabled,
                logo,
                use_metadata_info,
                metadata_url,
                entity_id,
                acs_url,
                certificate,
                attribute_mapping,
                groups_mapping,
                acs_allowed_callbacks,
                subject_name_id_type,
                subject_name_id_format,
                default_relay_state,
                force_authentication,
                logout_redirect_url,
            ),
        )
        return response.json()

    def update_oidc_application(
        self,
        id: str,
        name: str,
        login_page_url: str,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        enabled: Optional[bool] = True,
        force_authentication: Optional[bool] = False,
    ):
        """
        Update an existing OIDC sso application with the given parameters. IMPORTANT: All parameters are used as overrides
        to the existing sso application. Empty fields will override populated fields. Use carefully.

        Args:
        id (str): The ID of the sso application to update.
        name (str): Updated sso application name
        login_page_url (str): The URL where login page is hosted.
        description (str): Optional sso application description.
        logo (str): Optional sso application logo.
        enabled (bool): Optional (default True) does the sso application will be enabled or disabled.
        force_authentication (bool): Optional determine if the IdP should force the user to re-authenticate.

        Raise:
        AuthException: raised if update operation fails
        """

        uri = MgmtV1.sso_application_oidc_update_path
        self._http.post(
            uri,
            body=SSOApplication._compose_create_update_oidc_body(
                name,
                login_page_url,
                id,
                description,
                logo,
                enabled,
                force_authentication,
            ),
        )

    def update_saml_application(
        self,
        id: str,
        name: str,
        login_page_url: str,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        enabled: Optional[bool] = True,
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
    ):
        """
        Update an existing SAML sso application with the given parameters. IMPORTANT: All parameters are used as overrides
        to the existing sso application. Empty fields will override populated fields. Use carefully.

        Args:
        id (str): The ID of the sso application to update.
        name (str): Updated sso application name
        login_page_url (str): The URL where login page is hosted.
        description (str): Optional sso application description.
        logo (str): Optional sso application logo.
        enabled (bool): Optional (default True) does the sso application will be enabled or disabled.
        use_metadata_info (bool): Optional determine if SP info should be automatically fetched from metadata_url or by specified it by the entity_id, acs_url, certificate parameters.
        metadata_url (str): Optional SP metadata url which include all the SP SAML info.
        entity_id (str): Optional SP entity id.
        acs_url (str): Optional SP ACS (saml callback) url.
        certificate (str): Optional SP certificate, relevant only when SAML request must be signed.
        attribute_mapping (List[SAMLIDPAttributeMappingInfo]): Optional list of Descope (IdP) attributes to SP mapping.
        groups_mapping (List[SAMLIDPGroupsMappingInfo]): Optional list of Descope (IdP) roles that will be mapped to SP groups.
        acs_allowed_callbacks (List[str]): Optional list of urls wildcards strings represents the allowed ACS urls that will be accepted while arriving on the SAML request as SP callback urls.
        subject_name_id_type (str): Optional define the SAML Assertion subject name type, leave empty for using Descope user-id or set to "email"/"phone".
        subject_name_id_format (str): Optional define the SAML Assertion subject name format, leave empty for using "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".
        default_relay_state (str): Optional define the default relay state.
        force_authentication (bool): Optional determine if the IdP should force the user to re-authenticate.
        logout_redirect_url (str): Optional Target URL to which the user will be redirected upon logout completion.

        Raise:
        AuthException: raised if update operation fails
        """

        if use_metadata_info:
            if not metadata_url:
                raise Exception("metadata_url argument must be set")
        else:
            if not entity_id or not acs_url or not certificate:
                raise Exception("entity_id, acs_url, certificate arguments must be set")

        attribute_mapping = [] if attribute_mapping is None else attribute_mapping

        groups_mapping = [] if groups_mapping is None else groups_mapping

        acs_allowed_callbacks = (
            [] if acs_allowed_callbacks is None else acs_allowed_callbacks
        )

        uri = MgmtV1.sso_application_saml_update_path
        self._http.post(
            uri,
            body=SSOApplication._compose_create_update_saml_body(
                name,
                login_page_url,
                id,
                description,
                enabled,
                logo,
                use_metadata_info,
                metadata_url,
                entity_id,
                acs_url,
                certificate,
                attribute_mapping,
                groups_mapping,
                acs_allowed_callbacks,
                subject_name_id_type,
                subject_name_id_format,
                default_relay_state,
                force_authentication,
                logout_redirect_url,
            ),
        )

    def delete(
        self,
        id: str,
    ):
        """
        Delete an existing sso application. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        id (str): The ID of the sso application that's to be deleted.

        Raise:
        AuthException: raised if deletion operation fails
        """
        uri = MgmtV1.sso_application_delete_path
        # Using adapter's do_post which already includes management key in Authorization header
        self._http.post(uri, body={"id": id})

    def load(
        self,
        id: str,
    ) -> dict:
        """
        Load sso application by id.

        Args:
        id (str): The ID of the sso application to load.

        Return value (dict):
        Return dict in the format
             {"id":"<id>","name":"<name>","description":"<description>","enabled":true,"logo":"","appType":"saml","samlSettings":{"loginPageUrl":"","idpCert":"<cert>","useMetadataInfo":true,"metadataUrl":"","entityId":"","acsUrl":"","certificate":"","attributeMapping":[{"name":"email","type":"","value":"attrVal1"}],"groupsMapping":[{"name":"grp1","type":"","filterType":"roles","value":"","roles":[{"id":"myRoleId","name":"myRole"}]}],"idpMetadataUrl":"","idpEntityId":"","idpSsoUrl":"","acsAllowedCallbacks":[],"subjectNameIdType":"","subjectNameIdFormat":"", "defaultRelayState":"", "forceAuthentication": false, "idpLogoutUrl": "", "logoutRedirectUrl": ""},"oidcSettings":{"loginPageUrl":"","issuer":"","discoveryUrl":"", "forceAuthentication":false}}
        Containing the loaded sso application information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(MgmtV1.sso_application_load_path, params={"id": id})
        return response.json()

    def load_all(
        self,
    ) -> dict:
        """
        Load all sso applications.

        Return value (dict):
        Return dict in the format
             {
                                "apps": [
                                        {"id":"app1","name":"<name>","description":"<description>","enabled":true,"logo":"","appType":"saml","samlSettings":{"loginPageUrl":"","idpCert":"<cert>","useMetadataInfo":true,"metadataUrl":"","entityId":"","acsUrl":"","certificate":"","attributeMapping":[{"name":"email","type":"","value":"attrVal1"}],"groupsMapping":[{"name":"grp1","type":"","filterType":"roles","value":"","roles":[{"id":"myRoleId","name":"myRole"}]}],"idpMetadataUrl":"","idpEntityId":"","idpSsoUrl":"","acsAllowedCallbacks":[],"subjectNameIdType":"","subjectNameIdFormat":"", "defaultRelayState":"", "forceAuthentication": false, "idpLogoutUrl": "", "logoutRedirectUrl": ""},"oidcSettings":{"loginPageUrl":"","issuer":"","discoveryUrl":"", "forceAuthentication":false}},
                                {"id":"app2","name":"<name>","description":"<description>","enabled":true,"logo":"","appType":"saml","samlSettings":{"loginPageUrl":"","idpCert":"<cert>","useMetadataInfo":true,"metadataUrl":"","entityId":"","acsUrl":"","certificate":"","attributeMapping":[{"name":"email","type":"","value":"attrVal1"}],"groupsMapping":[{"name":"grp1","type":"","filterType":"roles","value":"","roles":[{"id":"myRoleId","name":"myRole"}]}],"idpMetadataUrl":"","idpEntityId":"","idpSsoUrl":"","acsAllowedCallbacks":[],"subjectNameIdType":"","subjectNameIdFormat":"", "defaultRelayState":"", "forceAuthentication": false, "idpLogoutUrl": "", "logoutRedirectUrl": ""},"oidcSettings":{"loginPageUrl":"","issuer":"","discoveryUrl":"", "forceAuthentication":false}}
                                ]
            }
        Containing the loaded sso applications information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(MgmtV1.sso_application_load_all_path)
        return response.json()

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
            "attributeMapping": saml_idp_attribute_mapping_info_to_dict(
                attribute_mapping
            ),
            "groupsMapping": saml_idp_groups_mapping_info_to_dict(groups_mapping),
            "acsAllowedCallbacks": acs_allowed_callbacks,
            "subjectNameIdType": subject_name_id_type,
            "subjectNameIdFormat": subject_name_id_format,
            "defaultRelayState": default_relay_state,
            "forceAuthentication": force_authentication,
            "logoutRedirectUrl": logout_redirect_url,
        }

        return body
