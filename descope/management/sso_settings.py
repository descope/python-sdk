from typing import List

from descope.auth import Auth
from descope.management.common import MgmtV1


class RoleMapping:
    def __init__(self, groups: List[str], role_name: str):
        self.groups = groups
        self.role_name = role_name


class SSOSettings:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def configure(
        self,
        tenant_id: str,
        idp_url: str,
        entity_id: str,
        idp_cert: str,
        redirect_url: str = None,
    ) -> None:
        """
        Configure SSO setting for a tenant manually. Alternatively, `configure_via_metadata` can be used instead.

        Args:
        tenant_id (str): The tenant ID to be configured
        idp_url (str): The URL for the identity provider.
        entity_id (str): The entity ID (in the IDP).
        idp_cert (str): The certificate provided by the IDP.
        redirect_url (str): An Optional Redirect URL after successful authentication.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._auth.do_post(
            MgmtV1.ssoConfigurePath,
            SSOSettings._compose_configure_body(
                tenant_id, idp_url, entity_id, idp_cert, redirect_url
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
        enabled (bool): Is SSO enabled
        idp_metadata_url (str): The URL to fetch SSO settings from.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._auth.do_post(
            MgmtV1.ssoMetadataPath,
            SSOSettings._compose_metadata_body(tenant_id, idp_metadata_url),
            pswd=self._auth.management_key,
        )

    def map_roles(
        self,
        tenant_id: str,
        role_mappings: List[RoleMapping],
    ):
        """
        Configure SSO role mapping from the IDP groups to the Descope roles.

        Args:
        tenant_id (str): The tenant ID to be configured
        role_mappings (List[RoleMapping]): A mapping between IDP groups and Descope roles.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._auth.do_post(
            MgmtV1.ssoRoleMappingPath,
            SSOSettings._compose_role_mapping_body(tenant_id, role_mappings),
            pswd=self._auth.management_key,
        )

    @staticmethod
    def _compose_configure_body(
        tenant_id: str,
        idp_url: str,
        entity_id: str,
        idp_cert: str,
        redirect_url: str = None,
    ) -> dict:
        return {
            "tenantId": tenant_id,
            "idpURL": idp_url,
            "entityId": entity_id,
            "idpCert": idp_cert,
            "redirectURL": redirect_url,
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
    def _compose_role_mapping_body(
        tenant_id: str,
        role_mapping: List[RoleMapping],
    ) -> dict:
        return {
            "tenantId": tenant_id,
            "roleMapping": SSOSettings._role_mapping_to_dict(role_mapping),
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
