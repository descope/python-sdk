from typing import List, Optional

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

    def create_batch(
        self,
        permissions: List[dict],
    ):
        """
        Create a batch of permissions in a single atomic transaction.

        Args:
        permissions (List[dict]): List of permission objects, each with:
            - name (str): permission name.
            - description (str): Optional description.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._http.post(
            MgmtV1.permission_create_batch_path,
            body={"permissions": permissions},
        )

    def update_batch(
        self,
        permissions: List[dict],
    ):
        """
        Update a batch of permissions in a single atomic transaction.

        Args:
        permissions (List[dict]): List of permission objects, each with:
            - name (str): current permission name (or id: permission ID).
            - newName (str): new permission name.
            - description (str): Optional new description.

        Raise:
        AuthException: raised if update operation fails
        """
        self._http.post(
            MgmtV1.permission_update_batch_path,
            body={"permissions": permissions},
        )

    def delete_batch(
        self,
        names: Optional[List[str]] = None,
        *,
        ids: Optional[List[str]] = None,
    ):
        """
        Delete a batch of permissions in a single atomic transaction.
        IMPORTANT: This action is irreversible. Use carefully.

        Args:
        names (List[str]): Optional list of permission names to delete.
        ids (List[str]): Optional list of permission IDs to delete (e.g. PERM...).

        Raise:
        AuthException: raised if deletion operation fails
        """
        body: dict = {}
        if names is not None:
            body["names"] = names
        if ids:
            body["ids"] = ids
        self._http.post(
            MgmtV1.permission_delete_batch_path,
            body=body,
        )

    def update(
        self,
        name: Optional[str] = None,
        new_name: str = "",
        description: Optional[str] = None,
        *,
        id: Optional[str] = None,
    ):
        """
        Update an existing permission. Identify by name or ID (exactly one required).
        IMPORTANT: All parameters are used as overrides to the existing permission.
        Empty fields will override populated fields. Use carefully.

        Args:
        name (str): current permission name (mutually exclusive with id).
        new_name (str): permission updated name.
        description (str): Optional description to briefly explain what this permission allows.
        id (str): permission ID, e.g. PERM... (mutually exclusive with name).

        Raise:
        AuthException: raised if update operation fails
        """
        body: dict = {"newName": new_name, "description": description}
        if id is not None:
            body["id"] = id
        else:
            body["name"] = name
        self._http.post(
            MgmtV1.permission_update_path,
            body=body,
        )

    def delete(
        self,
        name: Optional[str] = None,
        *,
        id: Optional[str] = None,
    ):
        """
        Delete an existing permission. Identify by name or ID (exactly one required).
        IMPORTANT: This action is irreversible. Use carefully.

        Args:
        name (str): The name of the permission to be deleted (mutually exclusive with id).
        id (str): The ID of the permission to be deleted, e.g. PERM... (mutually exclusive with name).

        Raise:
        AuthException: raised if deletion operation fails
        """
        body: dict = {}
        if id is not None:
            body["id"] = id
        else:
            body["name"] = name
        self._http.post(
            MgmtV1.permission_delete_path,
            body=body,
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
