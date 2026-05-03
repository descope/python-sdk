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
        private: Optional[bool] = None,
    ):
        """
        Create a new role.

        Args:
        name (str): role name.
        description (str): Optional description to briefly explain what this role allows.
        permission_names (List[str]): Optional list of names of permissions this role grants.
        tenant_id (str): Optional tenant ID to create the role in.
        default (bool): Optional marks this role as default role.
        private (bool): Optional marks this role as private role.

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
                "private": private,
            },
        )

    def create_batch(
        self,
        roles: List[dict],
    ):
        """
        Create a batch of roles in a single atomic transaction.

        Args:
        roles (List[dict]): List of role objects, each with:
            - name (str): role name.
            - description (str): Optional description.
            - permissionNames (List[str]): Optional list of permission names.
            - tenantId (str): Optional tenant ID.
            - default (bool): Optional default flag.
            - private (bool): Optional private flag.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._http.post(
            MgmtV1.role_create_batch_path,
            body={"roles": roles},
        )

    def update_batch(
        self,
        roles: List[dict],
    ):
        """
        Update a batch of roles in a single atomic transaction.

        Args:
        roles (List[dict]): List of role objects, each with:
            - name (str): current role name (or id: role ID).
            - newName (str): new role name.
            - description (str): Optional new description.
            - permissionNames (List[str]): Optional list of permission names.
            - tenantId (str): Optional tenant ID.
            - default (bool): Optional default flag.
            - private (bool): Optional private flag.

        Raise:
        AuthException: raised if update operation fails
        """
        self._http.post(
            MgmtV1.role_update_batch_path,
            body={"roles": roles},
        )

    def delete_batch(
        self,
        role_names: Optional[List[str]] = None,
        tenant_id: Optional[str] = None,
        *,
        role_ids: Optional[List[str]] = None,
    ):
        """
        Delete a batch of roles in a single atomic transaction.
        IMPORTANT: This action is irreversible. Use carefully.

        Args:
        role_names (List[str]): Optional list of role names to delete.
        tenant_id (str): Optional tenant ID the roles belong to.
        role_ids (List[str]): Optional list of role IDs to delete (e.g. ROL...).

        Raise:
        AuthException: raised if deletion operation fails
        """
        body: dict = {}
        if role_names:
            body["roleNames"] = role_names
        if tenant_id is not None:
            body["tenantId"] = tenant_id
        if role_ids:
            body["roleIds"] = role_ids
        self._http.post(
            MgmtV1.role_delete_batch_path,
            body=body,
        )

    def update(
        self,
        name: Optional[str] = None,
        new_name: str = "",
        description: Optional[str] = None,
        permission_names: Optional[List[str]] = None,
        tenant_id: Optional[str] = None,
        default: Optional[bool] = None,
        private: Optional[bool] = None,
        *,
        id: Optional[str] = None,
    ):
        """
        Update an existing role. Identify by name or ID (exactly one required).
        IMPORTANT: All parameters are used as overrides to the existing role.
        Empty fields will override populated fields. Use carefully.

        Args:
        name (str): current role name (mutually exclusive with id).
        new_name (str): role updated name.
        description (str): Optional description to briefly explain what this role allows.
        permission_names (List[str]): Optional list of names of permissions this role grants.
        tenant_id (str): Optional tenant ID to update the role in.
        default (bool): Optional marks this role as default role.
        private (bool): Optional marks this role as private role.
        id (str): role ID, e.g. ROL... (mutually exclusive with name).

        Raise:
        AuthException: raised if update operation fails
        """
        permission_names = [] if permission_names is None else permission_names
        body: dict = {
            "newName": new_name,
            "description": description,
            "permissionNames": permission_names,
            "tenantId": tenant_id,
            "default": default,
            "private": private,
        }
        if id is not None:
            body["id"] = id
        else:
            body["name"] = name
        self._http.post(
            MgmtV1.role_update_path,
            body=body,
        )

    def delete(
        self,
        name: Optional[str] = None,
        tenant_id: Optional[str] = None,
        *,
        id: Optional[str] = None,
    ):
        """
        Delete an existing role. Identify by name or ID (exactly one required).
        IMPORTANT: This action is irreversible. Use carefully.

        Args:
        name (str): The name of the role to be deleted (mutually exclusive with id).
        tenant_id (str): Optional tenant ID the role belongs to.
        id (str): The ID of the role to be deleted, e.g. ROL... (mutually exclusive with name).

        Raise:
        AuthException: raised if deletion operation fails
        """
        body: dict = {}
        if id is not None:
            body["id"] = id
        else:
            body["name"] = name
        if tenant_id is not None:
            body["tenantId"] = tenant_id
        self._http.post(
            MgmtV1.role_delete_path,
            body=body,
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
        role_ids: Optional[List[str]] = None,
    ) -> dict:
        """
        Search roles based on the given filters.

        Args:
        tenant_ids (List[str]): List of tenant ids to filter by
        role_names (List[str]): Only return matching roles to the given names
        role_name_like (str): Return roles that contain the given string ignoring case
        permission_names (List[str]): Only return roles that have the given permissions
        role_ids (List[str]): Only return roles matching the given IDs (e.g. ROL...)

        Return value (dict):
        Return dict in the format
             {"roles": [{"id": <id>, "name": <name>, "description": <description>, "permissionNames":[]}] }
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
        if role_ids is not None:
            body["roleIds"] = role_ids

        response = self._http.post(
            MgmtV1.role_search_path,
            body=body,
        )
        return response.json()
