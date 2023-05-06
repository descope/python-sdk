from typing import List

from descope._auth_base import AuthBase
from descope.management.common import (
    AssociatedTenant,
    MgmtV1,
    associated_tenants_to_dict,
)


class AccessKey(AuthBase):
    def create(
        self,
        name: str,
        expire_time: int = 0,
        role_names: List[str] = None,
        key_tenants: List[AssociatedTenant] = None,
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

        response = self._auth.do_post(
            MgmtV1.access_key_create_path,
            AccessKey._compose_create_body(name, expire_time, role_names, key_tenants),
            pswd=self._auth.management_key,
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
        response = self._auth.do_get(
            MgmtV1.access_key_load_path,
            {"id": id},
            pswd=self._auth.management_key,
        )
        return response.json()

    def search_all_access_keys(
        self,
        tenant_ids: List[str] = None,
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

        response = self._auth.do_post(
            MgmtV1.access_keys_search_path,
            {"tenantIds": tenant_ids},
            pswd=self._auth.management_key,
        )
        return response.json()

    def update(
        self,
        id: str,
        name: str,
    ):
        """
        Update an existing access key with the given various fields. IMPORTANT: All parameters are used as overrides
        to the existing access key. Empty fields will override populated fields. Use carefully.

        Args:
        id (str): The id of the access key to update.
        name (str): The updated access key name.

        Raise:
        AuthException: raised if update operation fails
        """
        self._auth.do_post(
            MgmtV1.access_key_update_path,
            {"id": id, "name": name},
            pswd=self._auth.management_key,
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
        self._auth.do_post(
            MgmtV1.access_key_deactivate_path,
            {"id": id},
            pswd=self._auth.management_key,
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
        self._auth.do_post(
            MgmtV1.access_key_activate_path,
            {"id": id},
            pswd=self._auth.management_key,
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
        self._auth.do_post(
            MgmtV1.access_key_delete_path,
            {"id": id},
            pswd=self._auth.management_key,
        )

    @staticmethod
    def _compose_create_body(
        name: str,
        expire_time: int,
        role_names: List[str],
        key_tenants: List[AssociatedTenant],
    ) -> dict:
        return {
            "name": name,
            "expireTime": expire_time,
            "roleNames": role_names,
            "keyTenants": associated_tenants_to_dict(key_tenants),
        }
