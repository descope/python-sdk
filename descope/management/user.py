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
        identifier: str,
        email: str = None,
        phone_number: str = None,
        display_name: str = None,
        role_names: List[str] = [],
        user_tenants: List[AssociatedTenant] = [],
    ) -> dict:
        """
        Create a new user. Users can have any number of optional fields, including email, phone number and authorization.

        Args:
        identifier (str): user identifier.
        email (str): Optional user email address.
        phone_number (str): Optional user phone number.
        display_name (str): Optional user display name.
        role_names (List[str]): An optional list of the user's roles without tenant association. These roles are
            mutually exclusive with the `user_tenant` roles, which take precedence over them.
        user_tenants (List[AssociatedTenant]): An optional list of the user's tenants, and optionally, their roles per tenant. These roles are
            mutually exclusive with the general `role_names`, and take precedence over them.

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
                identifier, email, phone_number, display_name, role_names, user_tenants
            ),
            pswd=self._auth.management_key,
        )
        return response.json()

    def update(
        self,
        identifier: str,
        email: str = None,
        phone_number: str = None,
        display_name: str = None,
        role_names: List[str] = [],
        user_tenants: List[AssociatedTenant] = [],
    ):
        """
        Update an existing user with the given various fields. IMPORTANT: All parameters are used as overrides
        to the existing user. Empty fields will override populated fields. Use carefully.

        Args:
        identifier (str): The identifier of the user to update.
        email (str): Optional user email address.
        phone_number (str): Optional user phone number.
        display_name (str): Optional user display name.
        role_names (List[str]): An optional list of the user's roles without tenant association. These roles are
            mutually exclusive with the `user_tenant` roles, which take precedence over the general roles.
        user_tenants (List[AssociatedTenant]): An optional list of the user's tenants, and optionally, their roles per tenant. These roles are
            mutually exclusive with the general `role_names`, and take precedence over them.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._auth.do_post(
            MgmtV1.userUpdatePath,
            User._compose_create_update_body(
                identifier, email, phone_number, display_name, role_names, user_tenants
            ),
            pswd=self._auth.management_key,
        )

    def delete(
        self,
        identifier: str,
    ):
        """
        Delete an existing user. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        identifier (str): The identifier of the user to be deleted.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._auth.do_post(
            MgmtV1.userDeletePath,
            {"identifier": identifier},
            pswd=self._auth.management_key,
        )

    def load(
        self,
        identifier: str,
    ) -> dict:
        """
        Load an existing user.

        Args:
        identifier (str): The identifier of the user to be loaded.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the loaded user information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_get(
            MgmtV1.userLoadPath,
            {"identifier": identifier},
            pswd=self._auth.management_key,
        )
        return response.json()

    def load_by_jwt_subject(
        self,
        jwt_subject: str,
    ) -> dict:
        """
        Load an existing user by JWT subject.
        The JWT subject can be found on the user's JWT.

        Args:
        jwt_subject (str): The JWT subject from the user's JWT.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the loaded user information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_get(
            MgmtV1.userLoadPath,
            {"jwtSubject": jwt_subject},
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

    @staticmethod
    def _compose_create_update_body(
        identifier: str,
        email: str,
        phone_number: str,
        display_name: str,
        role_names: List[str],
        user_tenants: List[AssociatedTenant],
    ) -> dict:
        return {
            "identifier": identifier,
            "email": email,
            "phoneNumber": phone_number,
            "displayName": display_name,
            "roleNames": role_names,
            "userTenants": associated_tenants_to_dict(user_tenants),
        }
