from typing import List

from descope.auth import Auth
from descope.management.common import MgmtV1


class Tenant:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def create(
        self,
        name: str,
        id: str = None,
        self_provisioning_domains: List[str] = [],
    ) -> dict:
        """
        Create a new tenant with the given name. Tenant IDs are provisioned automatically, but can be provided
        explicitly if needed. Both the name and ID must be unique per project.

        Args:
        name (str): The tenant's name
        id (str): Optional tenant ID.
        self_provisioning_domains (List[str]): An optional list of domain that are associated with this tenant.
            Users authenticating from these domains will be associated with this tenant.

        Return value (dict):
        Return dict in the format
             {"id": <id>}

        Raise:
        AuthException: raised if creation operation fails
        """
        uri = MgmtV1.tenantCreatePath
        response = self._auth.do_post(
            uri,
            Tenant._compose_create_update_body(name, id, self_provisioning_domains),
            pswd=self._auth.management_key,
        )
        return response.json()

    def update(
        self,
        id: str,
        name: str,
        self_provisioning_domains: List[str] = [],
    ):
        """
        Update an existing tenant with the given name and domains. IMPORTANT: All parameters are used as overrides
        to the existing tenant. Empty fields will override populated fields. Use carefully.

        Args:
        id (str): The ID of the tenant to update.
        name (str): Updated tenant name
        self_provisioning_domains (List[str]): An optional list of domain that are associated with this tenant.
            Users authenticating from these domains will be associated with this tenant.

        Raise:
        AuthException: raised if creation operation fails
        """
        uri = MgmtV1.tenantUpdatePath
        self._auth.do_post(
            uri,
            Tenant._compose_create_update_body(name, id, self_provisioning_domains),
            pswd=self._auth.management_key,
        )

    def delete(
        self,
        id: str,
    ):
        """
        Delete an existing tenant. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        id (str): The ID of the tenant that's to be deleted.

        Raise:
        AuthException: raised if creation operation fails
        """
        uri = MgmtV1.tenantDeletePath
        self._auth.do_post(uri, {"id": id}, pswd=self._auth.management_key)

    def load_all(
        self,
    ) -> dict:
        """
        Load all tenants.

        Return value (dict):
        Return dict in the format
             {"tenants": [{"id": <id>, "name": <name>, "selfProvisioningDomains": []}]}
        Containing the loaded tenant information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_get(
            MgmtV1.tenantLoadAllPath,
            pswd=self._auth.management_key,
        )
        return response.json()

    @staticmethod
    def _compose_create_update_body(
        name: str, id: str, self_provisioning_domains: List[str]
    ) -> dict:
        return {
            "name": name,
            "id": id,
            "selfProvisioningDomains": self_provisioning_domains,
        }
