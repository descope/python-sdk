from typing import List, Optional

from descope._http_base import HTTPBase
from descope.management.common import (
    AssociatedTenant,
    MgmtV1,
    associated_tenants_to_dict,
)


class AccessKey(HTTPBase):
    def create(
        self,
        name: str,
        expire_time: int = 0,
        role_names: Optional[List[str]] = None,
        key_tenants: Optional[List[AssociatedTenant]] = None,
        user_id: Optional[str] = None,
        custom_claims: Optional[dict] = None,
        description: Optional[str] = None,
        permitted_ips: Optional[List[str]] = None,
    ) -> dict:
        """
        Create a new access key.

        Args:
        name (str): Access key name.
        expire_time (int): Access key expiration. Leave at 0 to make it indefinite.
        role_names (List[str]): An optional list of the access key's roles without tenant association. These roles are
            mutually exclusive with the `key_tenant` roles, which take precedence over them.
        key_tenants (List[AssociatedTenant]): An optional list of the access key's tenants, and optionally, their roles per tenant. These roles are
            mutually exclusive with the general `role_names`, and take precedence over them.
        user_id (str): Bind access key to this user id
            If user_id is supplied, then authorizations will be ignored, and the access key will be bound to the user's authorization.
        custom_claims (dict): Optional, map of claims and their values that will be present in the JWT.
        description (str): an optional text the access key can hold.
        permitted_ips: (List[str]): An optional list of IP addresses or CIDR ranges that are allowed to use the access key.

        Return value (dict):
        Return dict in the format
            {
                "key": {},
                "cleartext": {}
            }
        Containing the created access key information and its cleartext. The key cleartext will only be returned on creation.
        Make sure to save it securely.

        Raise:
        AuthException: raised if create operation fails
        """
        role_names = [] if role_names is None else role_names
        key_tenants = [] if key_tenants is None else key_tenants

        response = self._http.post(
            MgmtV1.access_key_create_path,
            body=AccessKey._compose_create_body(
                name,
                expire_time,
                role_names,
                key_tenants,
                user_id,
                custom_claims,
                description,
                permitted_ips,
            ),
        )
        return response.json()

    def load(
        self,
        id: str,
    ) -> dict:
        """
        Load an existing access key.

        Args:
        id (str): The id of the access key to be loaded.

        Return value (dict):
        Return dict in the format
             {"key": {}}
        Containing the loaded access key information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._http.get(
            uri=MgmtV1.access_key_load_path,
            params={"id": id},
        )
        return response.json()

    def search_all_access_keys(
        self,
        tenant_ids: Optional[List[str]] = None,
    ) -> dict:
        """
        Search all access keys.

        Args:
        tenant_ids (List[str]): Optional list of tenant IDs to filter by

        Return value (dict):
        Return dict in the format
             {"keys": []}
        "keys" contains a list of all of the found users and their information

        Raise:
        AuthException: raised if search operation fails
        """
        tenant_ids = [] if tenant_ids is None else tenant_ids

        response = self._http.post(
            MgmtV1.access_keys_search_path,
            body={"tenantIds": tenant_ids},
        )
        return response.json()

    def update(
        self,
        id: str,
        name: str,
        description: Optional[str] = None,
    ):
        """
        Update an existing access key with the given various fields. IMPORTANT: id and name are mandatory fields.

        Args:
        id (str): The id of the access key to update.
        name (str): The updated access key name.
        description (str): The description of the access key to update. If not provided, it will not be overriden.

        Raise:
        AuthException: raised if update operation fails
        """
        self._http.post(
            MgmtV1.access_key_update_path,
            body={"id": id, "name": name, "description": description},
        )

    def deactivate(
        self,
        id: str,
    ):
        """
        Deactivate an existing access key. IMPORTANT: This deactivated key will not be usable from this stage.
        It will, however, persist, and can be activated again if needed.

        Args:
        id (str): The id of the access key to be deactivated.

        Raise:
        AuthException: raised if deactivation operation fails
        """
        self._http.post(
            MgmtV1.access_key_deactivate_path,
            body={"id": id},
        )

    def activate(
        self,
        id: str,
    ):
        """
        Activate an existing access key. IMPORTANT: Only deactivated keys can be activated again,
        and become usable once more. New access keys are active by default.

        Args:
        id (str): The id of the access key to be activate.

        Raise:
        AuthException: raised if activation operation fails
        """
        self._http.post(
            MgmtV1.access_key_activate_path,
            body={"id": id},
        )

    def delete(
        self,
        id: str,
    ):
        """
        Delete an existing access key. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        id (str): The id of the access key to be deleted.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._http.post(
            MgmtV1.access_key_delete_path,
            body={"id": id},
        )

    @staticmethod
    def _compose_create_body(
        name: str,
        expire_time: int,
        role_names: List[str],
        key_tenants: List[AssociatedTenant],
        user_id: Optional[str] = None,
        custom_claims: Optional[dict] = None,
        description: Optional[str] = None,
        permitted_ips: Optional[List[str]] = None,
    ) -> dict:
        return {
            "name": name,
            "expireTime": expire_time,
            "roleNames": role_names,
            "keyTenants": associated_tenants_to_dict(key_tenants),
            "userId": user_id,
            "customClaims": custom_claims,
            "description": description,
            "permittedIps": permitted_ips,
        }
