from typing import Optional

from descope._http_base import HTTPBase
from descope.management.common import MgmtV1


class Permission(HTTPBase):
    def create(
        self,
        name: str,
        description: Optional[str] = None,
    ):
        """
        Create a new permission.

        Args:
        name (str): permission name.
        description (str): Optional description to briefly explain what this permission allows.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._http.post(
            MgmtV1.permission_create_path,
            body={"name": name, "description": description},
        )

    def update(
        self,
        name: str,
        new_name: str,
        description: Optional[str] = None,
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
        self._http.post(
            MgmtV1.permission_update_path,
            body={"name": name, "newName": new_name, "description": description},
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
        self._http.post(
            MgmtV1.permission_delete_path,
            body={"name": name},
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
        response = self._http.get(
            MgmtV1.permission_load_all_path,
        )
        return response.json()
