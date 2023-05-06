from typing import List

from descope._auth_base import AuthBase
from descope.management.common import MgmtV1


class RoleMapping:
    """Map IDP group names to the Descope role name"""

    def __init__(self, groups: List[str], role_name: str):
        self.groups = groups
        self.role_name = role_name


class AttributeMapping:
    """Map Descope user attributes to IDP user attributes"""

    def __init__(
        self,
        name: str = None,
        email: str = None,
        phone_number: str = None,
        group: str = None,
    ):
        self.name = name
        self.email = email
        self.phone_number = phone_number
        self.group = group


class SSOSettings(AuthBase):
    def get_settings(
        self,
        tenant_id: str,
    ) -> dict:
        """
        Get SSO setting for the provided tenant_id.

        Args:
        tenant_id (str): The tenant ID of the desired SSO Settings

        Return value (dict):
        Containing the loaded SSO settings information.

        Raise:
        AuthException: raised if configuration operation fails
        """
        response = self._auth.do_get(
            MgmtV1.sso_settings_path,
            {"tenantId": tenant_id},
            pswd=self._auth.management_key,
        )
        return response.json()

    def configure(
        self,
        tenant_id: str,
        idp_url: str,
        entity_id: str,
        idp_cert: str,
        redirect_url: str = None,
        domain: str = None,
    ) -> None:
        """
        Configure SSO setting for a tenant manually. Alternatively, `configure_via_metadata` can be used instead.

        Args:
        tenant_id (str): The tenant ID to be configured
        idp_url (str): The URL for the identity provider.
        entity_id (str): The entity ID (in the IDP).
        idp_cert (str): The certificate provided by the IDP.
        redirect_url (str): An Optional Redirect URL after successful authentication.
        domain (str): An optional domain used to associate users authenticating via SSO with this tenant

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._auth.do_post(
            MgmtV1.sso_settings_path,
            SSOSettings._compose_configure_body(
                tenant_id, idp_url, entity_id, idp_cert, redirect_url, domain
            ),
            pswd=self._auth.management_key,
        )

    def configure_via_metadata(
        self,
        tenant_id: str,
        idp_metadata_url: str,
    ):
        """
        Configure SSO setting for am IDP metadata URL. Alternatively, `configure` can be used instead.

        Args:
        tenant_id (str): The tenant ID to be configured
        idp_metadata_url (str): The URL to fetch SSO settings from.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._auth.do_post(
            MgmtV1.sso_metadata_path,
            SSOSettings._compose_metadata_body(tenant_id, idp_metadata_url),
            pswd=self._auth.management_key,
        )

    def mapping(
        self,
        tenant_id: str,
        role_mappings: List[RoleMapping] = None,
        attribute_mapping: AttributeMapping = None,
    ):
        """
        Configure SSO role mapping from the IDP groups to the Descope roles.

        Args:
        tenant_id (str): The tenant ID to be configured
        role_mappings (List[RoleMapping]): A mapping between IDP groups and Descope roles.
        attribute_mapping (AttributeMapping): A mapping between IDP user attributes and descope attributes.

        Raise:
        AuthException: raised if configuration operation fails
        """
        role_mappings = [] if role_mappings is None else role_mappings
        attribute_mapping = [] if attribute_mapping is None else attribute_mapping

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
        redirect_url: str = None,
        domain: str = None,
    ) -> dict:
        return {
            "tenantId": tenant_id,
            "idpURL": idp_url,
            "entityId": entity_id,
            "idpCert": idp_cert,
            "redirectURL": redirect_url,
            "domain": domain,
        }

    @staticmethod
    def _compose_metadata_body(
        tenant_id: str,
        idp_metadata_url: str,
    ) -> dict:
        return {
            "tenantId": tenant_id,
            "idpMetadataURL": idp_metadata_url,
        }

    @staticmethod
    def _compose_mapping_body(
        tenant_id: str,
        role_mapping: List[RoleMapping],
        attribute_mapping: AttributeMapping,
    ) -> dict:
        return {
            "tenantId": tenant_id,
            "roleMappings": SSOSettings._role_mapping_to_dict(role_mapping),
            "attributeMapping": SSOSettings._attribute_mapping_to_dict(
                attribute_mapping
            ),
        }

    @staticmethod
    def _role_mapping_to_dict(role_mapping: List[RoleMapping]) -> list:
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
    def _attribute_mapping_to_dict(attribute_mapping: AttributeMapping) -> dict:
        return {
            "name": attribute_mapping.name,
            "email": attribute_mapping.email,
            "phoneNumber": attribute_mapping.phone_number,
            "group": attribute_mapping.group,
        }
