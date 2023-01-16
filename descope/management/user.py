from typing import List

from descope.auth import Auth
from descope.management.common import (
    AssociatedTenant,
    MgmtV1,
    associated_tenants_to_dict,
)


class User:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def create(
        self,
        login_id: str,
        email: str = None,
        phone: str = None,
        display_name: str = None,
        role_names: List[str] = [],
        user_tenants: List[AssociatedTenant] = [],
    ) -> dict:
        """
        Create a new user. Users can have any number of optional fields, including email, phone number and authorization.

        Args:
        login_id (str): user login ID.
        email (str): Optional user email address.
        phone (str): Optional user phone number.
        display_name (str): Optional user display name.
        role_names (List[str]): An optional list of the user's roles without tenant association. These roles are
            mutually exclusive with the `user_tenant` roles.
        user_tenants (List[AssociatedTenant]): An optional list of the user's tenants, and optionally, their roles per tenant. These roles are
            mutually exclusive with the general `role_names`.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the created user information.

        Raise:
        AuthException: raised if update operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userCreatePath,
            User._compose_create_update_body(
                login_id, email, phone, display_name, role_names, user_tenants
            ),
            pswd=self._auth.management_key,
        )
        return response.json()

    def update(
        self,
        login_id: str,
        email: str = None,
        phone: str = None,
        display_name: str = None,
        role_names: List[str] = [],
        user_tenants: List[AssociatedTenant] = [],
    ):
        """
        Update an existing user with the given various fields. IMPORTANT: All parameters are used as overrides
        to the existing user. Empty fields will override populated fields. Use carefully.

        Args:
        login_id (str): The login ID of the user to update.
        email (str): Optional user email address.
        phone (str): Optional user phone number.
        display_name (str): Optional user display name.
        role_names (List[str]): An optional list of the user's roles without tenant association. These roles are
            mutually exclusive with the `user_tenant` roles.
        user_tenants (List[AssociatedTenant]): An optional list of the user's tenants, and optionally, their roles per tenant. These roles are
            mutually exclusive with the general `role_names`.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._auth.do_post(
            MgmtV1.userUpdatePath,
            User._compose_create_update_body(
                login_id, email, phone, display_name, role_names, user_tenants
            ),
            pswd=self._auth.management_key,
        )

    def delete(
        self,
        login_id: str,
    ):
        """
        Delete an existing user. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        login_id (str): The login ID of the user to be deleted.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._auth.do_post(
            MgmtV1.userDeletePath,
            {"loginId": login_id},
            pswd=self._auth.management_key,
        )

    def load(
        self,
        login_id: str,
    ) -> dict:
        """
        Load an existing user.

        Args:
        login_id (str): The login ID of the user to be loaded.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the loaded user information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_get(
            MgmtV1.userLoadPath,
            {"loginId": login_id},
            pswd=self._auth.management_key,
        )
        return response.json()

    def load_by_user_id(
        self,
        user_id: str,
    ) -> dict:
        """
        Load an existing user by user ID.
        The user ID can be found on the user's JWT.

        Args:
        user_id (str): The user ID from the user's JWT.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the loaded user information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_get(
            MgmtV1.userLoadPath,
            {"userId": user_id},
            pswd=self._auth.management_key,
        )
        return response.json()

    def search_all(
        self,
        tenant_ids: List[str] = [],
        role_names: List[str] = [],
        limit: int = 0,
    ) -> dict:
        """
        Search all users.

        Args:
        tenant_ids (List[str]): Optional list of tenant IDs to filter by
        role_names (List[str]): Optional list of role names to filter by
        limit (int): Optional limit of the number of users returned. Leave empty for default.

        Return value (dict):
        Return dict in the format
             {"users": []}
        "users" contains a list of all of the found users and their information

        Raise:
        AuthException: raised if search operation fails
        """
        response = self._auth.do_post(
            MgmtV1.usersSearchPath,
            {"tenantIds": tenant_ids, "roleNames": role_names, "limit": limit},
            pswd=self._auth.management_key,
        )
        return response.json()

    def activate(
        self,
        login_id: str,
    ) -> dict:
        """
        Activate an existing user.

        Args:
        login_id (str): The login ID of the user to be activated.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if activate operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userUpdateStatusPath,
            {"loginId": login_id, "status": "enabled"},
            pswd=self._auth.management_key,
        )
        return response.json()

    def deactivate(
        self,
        login_id: str,
    ) -> dict:
        """
        Deactivate an existing user.

        Args:
        login_id (str): The login ID of the user to be deactivated.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if deactivate operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userUpdateStatusPath,
            {"loginId": login_id, "status": "disabled"},
            pswd=self._auth.management_key,
        )
        return response.json()

    def update_email(
        self,
        login_id: str,
        email: str = None,
        verified: bool = None,
    ) -> dict:
        """
        Update the email address for an existing user.

        Args:
        login_id (str): The login ID of the user to update the email for.
        email (str): The user email address. Leave empty to remove.
        verified (bool): Set to true for the user to be able to login with the email address.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the update operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userUpdateEmailPath,
            {"loginId": login_id, "email": email, "verified": verified},
            pswd=self._auth.management_key,
        )
        return response.json()

    def update_phone(
        self,
        login_id: str,
        phone: str = None,
        verified: bool = None,
    ) -> dict:
        """
        Update the phone number for an existing user.

        Args:
        login_id (str): The login ID of the user to update the phone for.
        phone (str): The user phone number. Leave empty to remove.
        verified (bool): Set to true for the user to be able to login with the phone number.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the update operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userUpdatePhonePath,
            {"loginId": login_id, "phone": phone, "verified": verified},
            pswd=self._auth.management_key,
        )
        return response.json()

    def update_display_name(
        self,
        login_id: str,
        display_name: str = None,
    ) -> dict:
        """
        Update the display name for an existing user.

        Args:
        login_id (str): The login ID of the user to update.
        display_name (str): Optional user display name. Leave empty to remove.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the update operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userUpdateNamePath,
            {"loginId": login_id, "displayName": display_name},
            pswd=self._auth.management_key,
        )
        return response.json()

    def add_roles(
        self,
        login_id: str,
        role_names: List[str],
    ) -> dict:
        """
        Add roles to a user without tenant association. Use add_tenant_roles
        for users that are part of a multi-tenant project.

        Args:
        login_id (str): The login ID of the user to update.
        role_names (List[str]): A list of roles to add to a user without tenant association.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userAddRolePath,
            {"loginId": login_id, "roleNames": role_names},
            pswd=self._auth.management_key,
        )
        return response.json()

    def remove_roles(
        self,
        login_id: str,
        role_names: List[str],
    ) -> dict:
        """
        Remove roles from a user without tenant association. Use remove_tenant_roles
        for users that are part of a multi-tenant project.

        Args:
        login_id (str): The login ID of the user to update.
        role_names (List[str]): A list of roles to remove from a user without tenant association.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userRemoveRolePath,
            {"loginId": login_id, "roleNames": role_names},
            pswd=self._auth.management_key,
        )
        return response.json()

    def add_tenant(
        self,
        login_id: str,
        tenant_id: str,
    ) -> dict:
        """
        Add a tenant association to an existing user.

        Args:
        login_id (str): The login ID of the user to update.
        tenant_id (str): The ID of the tenant to add to the user.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userAddTenantPath,
            {"loginId": login_id, "tenantId": tenant_id},
            pswd=self._auth.management_key,
        )
        return response.json()

    def remove_tenant(
        self,
        login_id: str,
        tenant_id: str,
    ) -> dict:
        """
        Remove a tenant association from an existing user.

        Args:
        login_id (str): The login ID of the user to update.
        tenant_id (str): The ID of the tenant to add to the user.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userRemoveTenantPath,
            {"loginId": login_id, "tenantId": tenant_id},
            pswd=self._auth.management_key,
        )
        return response.json()

    def add_tenant_roles(
        self,
        login_id: str,
        tenant_id: str,
        role_names: List[str],
    ) -> dict:
        """
        Add roles to a user in a specific tenant.

        Args:
        login_id (str): The login ID of the user to update.
        tenant_id (str): The ID of the user's tenant.
        role_names (List[str]): A list of roles to add to the user.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userAddRolePath,
            {"loginId": login_id, "tenantId": tenant_id, "roleNames": role_names},
            pswd=self._auth.management_key,
        )
        return response.json()

    def remove_tenant_roles(
        self,
        login_id: str,
        tenant_id: str,
        role_names: List[str],
    ) -> dict:
        """
        Remove roles from a user in a specific tenant.

        Args:
        login_id (str): The login ID of the user to update.
        tenant_id (str): The ID of the user's tenant.
        role_names (List[str]): A list of roles to remove from the user.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.userRemoveRolePath,
            {"loginId": login_id, "tenantId": tenant_id, "roleNames": role_names},
            pswd=self._auth.management_key,
        )
        return response.json()

    @staticmethod
    def _compose_create_update_body(
        login_id: str,
        email: str,
        phone: str,
        display_name: str,
        role_names: List[str],
        user_tenants: List[AssociatedTenant],
    ) -> dict:
        return {
            "loginId": login_id,
            "email": email,
            "phone": phone,
            "displayName": display_name,
            "roleNames": role_names,
            "userTenants": associated_tenants_to_dict(user_tenants),
        }
