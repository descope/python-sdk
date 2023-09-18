from typing import List, Optional

from descope._auth_base import AuthBase
from descope.management.common import MgmtV1


class Role(AuthBase):
    def create(
        self,
        name: str,
        description: Optional[str] = None,
        permission_names: Optional[List[str]] = None,
    ):
        """
        Create a new role.

        Args:
        name (str): role name.
        description (str): Optional description to briefly explain what this role allows.
        permission_names (List[str]): Optional list of names of permissions this role grants.

        Raise:
        AuthException: raised if creation operation fails
        """
        permission_names = [] if permission_names is None else permission_names

        self._auth.do_post(
            MgmtV1.role_create_path,
            {
                "name": name,
                "description": description,
                "permissionNames": permission_names,
            },
            pswd=self._auth.management_key,
        )

    def update(
        self,
        name: str,
        new_name: str,
        description: Optional[str] = None,
        permission_names: Optional[List[str]] = None,
    ):
        """
        Update an existing role with the given various fields. IMPORTANT: All parameters are used as overrides
        to the existing role. Empty fields will override populated fields. Use carefully.

        Args:
        name (str): role name.
        new_name (str): role updated name.
        description (str): Optional description to briefly explain what this role allows.
        permission_names (List[str]): Optional list of names of permissions this role grants.

        Raise:
        AuthException: raised if update operation fails
        """
        permission_names = [] if permission_names is None else permission_names
        self._auth.do_post(
            MgmtV1.role_update_path,
            {
                "name": name,
                "newName": new_name,
                "description": description,
                "permissionNames": permission_names,
            },
            pswd=self._auth.management_key,
        )

    def delete(
        self,
        name: str,
    ):
        """
        Delete an existing role. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        name (str): The name of the role to be deleted.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._auth.do_post(
            MgmtV1.role_delete_path,
            {"name": name},
            pswd=self._auth.management_key,
        )

    def load_all(
        self,
    ) -> dict:
        """
        Load all roles.

        Return value (dict):
        Return dict in the format
             {"roles": [{"name": <name>, "description": <description>, "permissionNames":[]}] }
        Containing the loaded role information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_get(
            uri=MgmtV1.role_load_all_path,
            pswd=self._auth.management_key,
        )
        return response.json()
