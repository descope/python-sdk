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
        mgmt_key: str,
        tenant_id: str,
        enabled: bool,
        idp_url: str,
        entity_id: str,
        idp_cert: str,
        redirect_url: str,
    ) -> dict:
        """
        Configure SSO setting for a tenant manually. Alternatively, `configure_via_metadata` can be used instead.

        Args:
        mgmt_key (str): A management key generated in the Descope console. All management functions require it.
        tenant_id (str): The tenant ID to be configured
        enabled (str): Is SSO enabled
        idp_url (str): The URL for the identity provider.
        entity_id (str): The entity ID (in the IDP).
        idp_cert (str): The certificate provided by the IDP.
        redirect_url (str): Redirect URL after successful authentication.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._auth.do_post(
            MgmtV1.ssoConfigurePath,
            _compose_configure_body(
                tenant_id, enabled, idp_url, entity_id, idp_cert, redirect_url
            ),
            pswd=mgmt_key,
        )

    def configure_via_metadata(
        self,
        mgmt_key: str,
        tenant_id: str,
        enabled: bool,
        idp_metadata_url: str,
    ):
        """
        Configure SSO setting for am IDP metadata URL. Alternatively, `configure` can be used instead.

        Args:
        mgmt_key (str): A management key generated in the Descope console. All management functions require it.
        tenant_id (str): The tenant ID to be configured
        enabled (str): Is SSO enabled
        idp_metadata_url (str): The URL to fetch SSO settings from.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._auth.do_post(
            MgmtV1.ssoMetadataPath,
            _compose_metadata_body(tenant_id, enabled, idp_metadata_url),
            pswd=mgmt_key,
        )

    def map_roles(
        self,
        mgmt_key: str,
        tenant_id: str,
        role_mapping: List[RoleMapping],
    ):
        """
        Configure SSO role mapping from the IDP groups to the Descope roles.

        Args:
        mgmt_key (str): A management key generated in the Descope console. All management functions require it.
        tenant_id (str): The tenant ID to be configured
        role_mapping (List[RoleMapping]): A mapping between IDP groups and Descope roles.

        Raise:
        AuthException: raised if configuration operation fails
        """
        self._auth.do_post(
            MgmtV1.ssoRoleMappingPath,
            _compose_role_mapping_body(tenant_id, role_mapping),
            pswd=mgmt_key,
        )


class UserTenants:
    def __init__(self, tenant_id: str, role_names: List[str]):
        self.tenant_id = tenant_id
        self.role_names = role_names


@staticmethod
def _compose_configure_body(
    tenant_id: str,
    enabled: bool,
    idp_url: str,
    entity_id: str,
    idp_cert: str,
    redirect_url: str,
) -> dict:
    return {
        "tenantId": tenant_id,
        "enabled": enabled,
        "idpURL": idp_url,
        "entityId": entity_id,
        "idpCert": idp_cert,
        "redirectURL": redirect_url,
    }


@staticmethod
def _compose_metadata_body(
    tenant_id: str,
    enabled: bool,
    idp_metadata_url: str,
) -> dict:
    return {
        "tenantId": tenant_id,
        "enabled": enabled,
        "idpMetadataURL": idp_metadata_url,
    }


@staticmethod
def _compose_role_mapping_body(
    tenant_id: str,
    role_mapping: List[RoleMapping],
) -> dict:
    return {
        "tenantId": tenant_id,
        "roleMapping": _role_mapping_to_dict(role_mapping),
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
