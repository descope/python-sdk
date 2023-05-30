from descope._auth_base import AuthBase
from descope.management.common import MgmtV1


class Permission(AuthBase):
    def create(
        self,
        name: str,
        description: str = None,
    ):
        """
        Create a new permission.

        Args:
        name (str): permission name.
        description (str): Optional description to briefly explain what this permission allows.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._auth.do_post(
            MgmtV1.permission_create_path,
            {"name": name, "description": description},
            pswd=self._auth.management_key,
        )

    def update(
        self,
        name: str,
        new_name: str,
        description: str = None,
    ):
        """
        Update an existing permission with the given various fields. IMPORTANT: All parameters are used as overrides
        to the existing permission. Empty fields will override populated fields. Use carefully.

        Args:
        name (str): permission name.
        new_name (str): permission updated name.
        description (str): Optional description to briefly explain what this permission allows.

        Raise:
        AuthException: raised if update operation fails
        """
        self._auth.do_post(
            MgmtV1.permission_update_path,
            {"name": name, "newName": new_name, "description": description},
            pswd=self._auth.management_key,
        )

    def delete(
        self,
        name: str,
    ):
        """
        Delete an existing permission. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        name (str): The name of the permission to be deleted.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._auth.do_post(
            MgmtV1.permission_delete_path,
            {"name": name},
            pswd=self._auth.management_key,
        )

    def load_all(
        self,
    ) -> dict:
        """
        Load all permissions.

        Return value (dict):
        Return dict in the format
             {"permissions": [{"name": <name>, "description": <description>, "systemDefault":<True/False>}]}
        Containing the loaded permission information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_get(
            uri=MgmtV1.permission_load_all_path,
            pswd=self._auth.management_key,
        )
        return response.json()
