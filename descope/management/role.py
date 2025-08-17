from __future__ import annotations

from typing import List, Optional

from descope._http_base import HTTPBase
from descope.management.common import MgmtV1


class Role(HTTPBase):
    def create(
        self,
        name: str,
        description: Optional[str] = None,
        permission_names: Optional[List[str]] = None,
        tenant_id: Optional[str] = None,
        default: Optional[bool] = None,
    ):
        """
        Create a new role.

        Args:
        name (str): role name.
        description (str): Optional description to briefly explain what this role allows.
        permission_names (List[str]): Optional list of names of permissions this role grants.
        tenant_id (str): Optional tenant ID to create the role in.
        default (bool): Optional marks this role as default role.

        Raise:
        AuthException: raised if creation operation fails
        """
        permission_names = [] if permission_names is None else permission_names

        self._http.post(
            MgmtV1.role_create_path,
            body={
                "name": name,
                "description": description,
                "permissionNames": permission_names,
                "tenantId": tenant_id,
                "default": default,
            },
        )

    def update(
        self,
        name: str,
        new_name: str,
        description: Optional[str] = None,
        permission_names: Optional[List[str]] = None,
        tenant_id: Optional[str] = None,
        default: Optional[bool] = None,
    ):
        """
        Update an existing role with the given various fields. IMPORTANT: All parameters are used as overrides
        to the existing role. Empty fields will override populated fields. Use carefully.

        Args:
        name (str): role name.
        new_name (str): role updated name.
        description (str): Optional description to briefly explain what this role allows.
        permission_names (List[str]): Optional list of names of permissions this role grants.
        tenant_id (str): Optional tenant ID to update the role in.
        default (bool): Optional marks this role as default role.

        Raise:
        AuthException: raised if update operation fails
        """
        permission_names = [] if permission_names is None else permission_names
        self._http.post(
            MgmtV1.role_update_path,
            body={
                "name": name,
                "newName": new_name,
                "description": description,
                "permissionNames": permission_names,
                "tenantId": tenant_id,
                "default": default,
            },
        )

    def delete(
        self,
        name: str,
        tenant_id: Optional[str] = None,
    ):
        """
        Delete an existing role. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        name (str): The name of the role to be deleted.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._http.post(
            MgmtV1.role_delete_path,
            body={"name": name, "tenantId": tenant_id},
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
        response = self._http.get(
            MgmtV1.role_load_all_path,
        )
        return response.json()

    def search(
        self,
        tenant_ids: Optional[List[str]] = None,
        role_names: Optional[List[str]] = None,
        role_name_like: Optional[str] = None,
        permission_names: Optional[List[str]] = None,
        include_project_roles: Optional[bool] = None,
    ) -> dict:
        """
        Search roles based on the given filters.

        Args:
        tenant_ids (List[str]): List of tenant ids to filter by
        role_names (List[str]): Only return matching roles to the given names
        role_name_like (str): Return roles that contain the given string ignoring case
        permission_names (List[str]): Only return roles that have the given permissions

        Return value (dict):
        Return dict in the format
             {"roles": [{"name": <name>, "description": <description>, "permissionNames":[]}] }
        Containing the loaded role information.

        Raise:
        AuthException: raised if load operation fails
        """
        body: dict[str, str | bool | List[str]] = {}
        if tenant_ids is not None:
            body["tenantIds"] = tenant_ids
        if role_names is not None:
            body["roleNames"] = role_names
        if role_name_like is not None:
            body["roleNameLike"] = role_name_like
        if permission_names is not None:
            body["permissionNames"] = permission_names
        if include_project_roles is not None:
            body["includeProjectRoles"] = include_project_roles

        response = self._http.post(
            MgmtV1.role_search_path,
            body=body,
        )
        return response.json()
