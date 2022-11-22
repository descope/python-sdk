from typing import List

from descope.auth import Auth
from descope.management.common import MgmtV1


class Tenant:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def create(
        self,
        mgmt_key: str,
        name: str,
        id: str = None,
        self_provisioning_domains: List[str] = None,
    ) -> dict:
        """
        Create a new tenant with the given name. Tenant IDs are provisioned automatically, but can be provided
        explicitly if needed. Both the name and ID must be unique per project.

        Args:
        mgmt_key (str): A management key generated in the Descope console. All management functions require it.
        name (str): The tenant's name
        id (str): Optional tenant ID.
        self_provisioning_domains (List[str]): An optional list of domain that are associated with this tenant.
            Users authenticating from these domains will be associated with this tenant.

        Raise:
        AuthException: raised if creation operation fails
        """
        uri = MgmtV1.tenantCreatePath
        response = self._auth.do_post(
            uri,
            Tenant._compose_create_update_body(name, id, self_provisioning_domains),
            pswd=mgmt_key,
        )
        return response.json()

    def update(
        self,
        mgmt_key: str,
        id: str,
        name: str = None,
        self_provisioning_domains: List[str] = None,
    ):
        """
        Update an existing tenant with the given name and domains. IMPORTANT: All parameters are used as overrides
        to the existing tenant. Use carefully.

        Args:
        mgmt_key (str): A management key generated in the Descope console. All management functions require it.
        id (str): The ID of the tenant to update.
        name (str): Updated tenant's name
        self_provisioning_domains (List[str]): An optional list of domain that are associated with this tenant.
            Users authenticating from these domains will be associated with this tenant.

        Raise:
        AuthException: raised if creation operation fails
        """
        uri = MgmtV1.tenantUpdatePath
        self._auth.do_post(
            uri,
            Tenant._compose_create_update_body(name, id, self_provisioning_domains),
            pswd=mgmt_key,
        )

    def delete(
        self,
        mgmt_key: str,
        id: str,
    ):
        """
        Delete an existing tenant. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        mgmt_key (str): A management key generated in the Descope console. All management functions require it.
        id (str): The ID of the tenant that's to be deleted.

        Raise:
        AuthException: raised if creation operation fails
        """
        uri = MgmtV1.tenantDeletePath
        self._auth.do_post(uri, {"id": id}, pswd=mgmt_key)

    @staticmethod
    def _compose_create_update_body(
        name: str, id: str, self_provisioning_domains: List[str]
    ) -> dict:
        return {
            "name": name,
            "id": id,
            "selfProvisioningDomains": self_provisioning_domains,
        }
