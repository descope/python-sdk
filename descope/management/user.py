from typing import List

from descope.auth import Auth
from descope.management.common import MgmtV1


class UserTenants:
    def __init__(
        self, tenant_id: str, role_names: List[str]
    ):
        self.tenant_id = tenant_id
        self.role_names = role_names

class User:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def create(
        self,
        mgmt_key: str,
        identifier: str,
        email: str = None,
        phone_number: str = None,
        display_name: str = None,
        role_names: List[str] = None,
        user_tenants: List[UserTenants] = None
    ) -> dict:
        """
        Create a new user. User's can have any number of optional fields, including email, phone number and authorization.

        Args:
        mgmt_key (str): A management key generated in the Descope console. All management functions require it.
        identifier (str): user identifier.
        email (str): Optional user email address.
        phone_number (str): Optional user phone number.
        display_name (str): Optional user display name.
        role_names (List[str]): An optional list of the user's roles without tenant association.
        user_tenants (List[str]): An optional list of the user's roles per tenant.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._auth.do_post(
            MgmtV1.userCreatePath,
            _compose_create_update_body(identifier, email, phone_number, display_name, role_names, user_tenants),
            pswd=mgmt_key,
        )

    def update(
        self,
        mgmt_key: str,
        identifier: str,
        email: str = None,
        phone_number: str = None,
        display_name: str = None,
        role_names: List[str] = None,
        user_tenants: List[UserTenants] = None
    ):
        """
        Update an existing user with the given various fields. IMPORTANT: All parameters are used as overrides
        to the existing user. Use carefully.

        Args:
        mgmt_key (str): A management key generated in the Descope console. All management functions require it.
        identifier (str): The identifier of the user to update.
        email (str): Optional user email address.
        phone_number (str): Optional user phone number.
        display_name (str): Optional user display name.
        role_names (List[str]): An optional list of the user's roles without tenant association.
        user_tenants (List[str]): An optional list of the user's roles per tenant.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._auth.do_post(
            MgmtV1.userUpdatePath,
            _compose_create_update_body(identifier, email, phone_number, display_name, role_names, user_tenants),
            pswd=mgmt_key,
        )
      
    def delete(
        self,
        mgmt_key: str,
        identifier: str,
    ):
        """
        Delete an existing user. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        mgmt_key (str): A management key generated in the Descope console. All management functions require it.
        identifier (str): The identifier of the user that's to be deleted.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._auth.do_post(
            MgmtV1.userDeletePath,
            {"identifier": identifier},
            pswd=mgmt_key,
        )

class UserTenants:
    def __init__(
        self, tenant_id: str, role_names: List[str]
    ):
        self.tenant_id = tenant_id
        self.role_names = role_names

@staticmethod
def _compose_create_update_body(
    identifier: str,
    email: str,
    phone_number: str,
    display_name: str,
    role_names: List[str],
    user_tenants: List[UserTenants],
) -> dict:
    return {
        "identifier": identifier,
        "email": email,
        "phoneNumber": phone_number,
        "displayName": display_name,
        "roleNames": role_names,
        "userTenants": _user_tenants_to_dict(user_tenants)
    }

@staticmethod
def _user_tenants_to_dict(user_tenants: List[UserTenants]) -> list:
    if not user_tenants:
        return None

    user_tenant_list = []
    for user_tenant in user_tenants:
        user_tenant_list.append(
            {
                "tenantId": user_tenant.tenant_id,
                "roleNames": user_tenant.role_names,
            }
        )
    return user_tenant_list
