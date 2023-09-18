from typing import List, Optional, Union

from descope._auth_base import AuthBase
from descope.auth import Auth
from descope.common import DeliveryMethod
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.management.common import (
    AssociatedTenant,
    MgmtV1,
    associated_tenants_to_dict,
)


class User(AuthBase):
    def create(
        self,
        login_id: str,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        display_name: Optional[str] = None,
        role_names: Optional[List[str]] = None,
        user_tenants: Optional[List[AssociatedTenant]] = None,
        picture: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
        verified_email: Optional[bool] = None,
        verified_phone: Optional[bool] = None,
        invite_url: Optional[str] = None,
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
        picture (str): Optional url for user picture
        custom_attributes (dict): Optional, set the different custom attributes values of the keys that were previously configured in Descope console app

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the created user information.

        Raise:
        AuthException: raised if update operation fails
        """
        role_names = [] if role_names is None else role_names
        user_tenants = [] if user_tenants is None else user_tenants

        response = self._auth.do_post(
            MgmtV1.user_create_path,
            User._compose_create_body(
                login_id,
                email,
                phone,
                display_name,
                role_names,
                user_tenants,
                False,
                False,
                picture,
                custom_attributes,
                verified_email,
                verified_phone,
                invite_url,
            ),
            pswd=self._auth.management_key,
        )
        return response.json()

    def create_test_user(
        self,
        login_id: str,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        display_name: Optional[str] = None,
        role_names: Optional[List[str]] = None,
        user_tenants: Optional[List[AssociatedTenant]] = None,
        picture: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
        verified_email: Optional[bool] = None,
        verified_phone: Optional[bool] = None,
        invite_url: Optional[str] = None,
    ) -> dict:
        """
        Create a new test user.
        The login_id is required and will determine what the user will use to sign in.
        Make sure the login id is unique for test. All other fields are optional.

        Args:
        login_id (str): user login ID.
        email (str): Optional user email address.
        phone (str): Optional user phone number.
        display_name (str): Optional user display name.
        role_names (List[str]): An optional list of the user's roles without tenant association. These roles are
            mutually exclusive with the `user_tenant` roles.
        user_tenants (List[AssociatedTenant]): An optional list of the user's tenants, and optionally, their roles per tenant. These roles are
            mutually exclusive with the general `role_names`.
        picture (str): Optional url for user picture
        custom_attributes (dict): Optional, set the different custom attributes values of the keys that were previously configured in Descope console app

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the created test user information.

        Raise:
        AuthException: raised if update operation fails
        """
        role_names = [] if role_names is None else role_names
        user_tenants = [] if user_tenants is None else user_tenants

        response = self._auth.do_post(
            MgmtV1.user_create_path,
            User._compose_create_body(
                login_id,
                email,
                phone,
                display_name,
                role_names,
                user_tenants,
                False,
                True,
                picture,
                custom_attributes,
                verified_email,
                verified_phone,
                invite_url,
            ),
            pswd=self._auth.management_key,
        )
        return response.json()

    def invite(
        self,
        login_id: str,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        display_name: Optional[str] = None,
        role_names: Optional[List[str]] = None,
        user_tenants: Optional[List[AssociatedTenant]] = None,
        picture: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
        verified_email: Optional[bool] = None,
        verified_phone: Optional[bool] = None,
        invite_url: Optional[str] = None,
    ) -> dict:
        """
        Create a new user and invite them via an email message.

        Functions exactly the same as the `create` function with the additional invitation
            behavior. See the documentation above for the general creation behavior.

        IMPORTANT: Since the invitation is sent by email, make sure either
            the email is explicitly set, or the login_id itself is an email address.
            You must configure the invitation URL in the Descope console prior to
            calling the method.
        """
        role_names = [] if role_names is None else role_names
        user_tenants = [] if user_tenants is None else user_tenants

        response = self._auth.do_post(
            MgmtV1.user_create_path,
            User._compose_create_body(
                login_id,
                email,
                phone,
                display_name,
                role_names,
                user_tenants,
                True,
                False,
                picture,
                custom_attributes,
                verified_email,
                verified_phone,
                invite_url,
            ),
            pswd=self._auth.management_key,
        )
        return response.json()

    def update(
        self,
        login_id: str,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        display_name: Optional[str] = None,
        role_names: Optional[List[str]] = None,
        user_tenants: Optional[List[AssociatedTenant]] = None,
        picture: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
        verified_email: Optional[bool] = None,
        verified_phone: Optional[bool] = None,
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
        picture (str): Optional url for user picture
        custom_attributes (dict): Optional, set the different custom attributes values of the keys that were previously configured in Descope console app

        Raise:
        AuthException: raised if creation operation fails
        """
        role_names = [] if role_names is None else role_names
        user_tenants = [] if user_tenants is None else user_tenants

        self._auth.do_post(
            MgmtV1.user_update_path,
            User._compose_update_body(
                login_id,
                email,
                phone,
                display_name,
                role_names,
                user_tenants,
                False,
                picture,
                custom_attributes,
                verified_email,
                verified_phone,
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
            MgmtV1.user_delete_path,
            {"loginId": login_id},
            pswd=self._auth.management_key,
        )

    def delete_all_test_users(
        self,
    ):
        """
        Delete all test users in the project. IMPORTANT: This action is irreversible. Use carefully.

        Raise:
        AuthException: raised if creation operation fails
        """
        self._auth.do_delete(
            MgmtV1.user_delete_all_test_users_path,
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
            uri=MgmtV1.user_load_path,
            params={"loginId": login_id},
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
            uri=MgmtV1.user_load_path,
            params={"userId": user_id},
            pswd=self._auth.management_key,
        )
        return response.json()

    def search_all(
        self,
        tenant_ids: Optional[List[str]] = None,
        role_names: Optional[List[str]] = None,
        limit: int = 0,
        page: int = 0,
        test_users_only: bool = False,
        with_test_user: bool = False,
        custom_attributes: Optional[dict] = None,
        statuses: Optional[List[str]] = None,
    ) -> dict:
        """
        Search all users.

        Args:
        tenant_ids (List[str]): Optional list of tenant IDs to filter by
        role_names (List[str]): Optional list of role names to filter by
        limit (int): Optional limit of the number of users returned. Leave empty for default.
        page (int): Optional pagination control. Pages start at 0 and must be non-negative.
        test_users_only (bool): Optional filter only test users.
        with_test_user (bool): Optional include test users in search.

        Return value (dict):
        Return dict in the format
             {"users": []}
        "users" contains a list of all of the found users and their information

        Raise:
        AuthException: raised if search operation fails
        """
        tenant_ids = [] if tenant_ids is None else tenant_ids
        role_names = [] if role_names is None else role_names

        if limit < 0:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "limit must be non-negative"
            )

        if page < 0:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "page must be non-negative"
            )
        body = {
            "tenantIds": tenant_ids,
            "roleNames": role_names,
            "limit": limit,
            "page": page,
            "testUsersOnly": test_users_only,
            "withTestUser": with_test_user,
        }
        if statuses is not None:
            body["statuses"] = statuses

        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes

        response = self._auth.do_post(
            MgmtV1.users_search_path,
            body=body,
            pswd=self._auth.management_key,
        )
        return response.json()

    def get_provider_token(
        self,
        login_id: str,
        provider: str,
    ) -> dict:
        """
        Get the provider token for the given login ID.
        Only users that sign-in using social providers will have token.
        Note: The 'Manage tokens from provider' setting must be enabled.

        Args:
        login_id (str): The login ID of the user.
        provider (str): The provider name (google, facebook, etc').

        Return value (dict):
        Return dict in the format
             {"provider": "", "providerUserId": "", "accessToken": "", "expiration": "", "scopes": "[]"}
        Containing the provider token of the given user and provider.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_get(
            MgmtV1.user_get_provider_token,
            {"loginId": login_id, "provider": provider},
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
            MgmtV1.user_update_status_path,
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
            MgmtV1.user_update_status_path,
            {"loginId": login_id, "status": "disabled"},
            pswd=self._auth.management_key,
        )
        return response.json()

    def update_login_id(
        self,
        login_id: str,
        new_login_id: Optional[str] = None,
    ) -> dict:
        """
        Update login id of user, leave new login empty to remove the ID.
        A user must have at least one login ID. Trying to remove the last one will fail.

        Args:
        login_id (str): The login ID of the user to update.
        new_login_id (str): New login ID to set for the user.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the update operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_update_login_id_path,
            {"loginId": login_id, "newLoginId": new_login_id},
            pswd=self._auth.management_key,
        )
        return response.json()

    def update_email(
        self,
        login_id: str,
        email: Optional[str] = None,
        verified: Optional[bool] = None,
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
            MgmtV1.user_update_email_path,
            {"loginId": login_id, "email": email, "verified": verified},
            pswd=self._auth.management_key,
        )
        return response.json()

    def update_phone(
        self,
        login_id: str,
        phone: Optional[str] = None,
        verified: Optional[bool] = None,
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
            MgmtV1.user_update_phone_path,
            {"loginId": login_id, "phone": phone, "verified": verified},
            pswd=self._auth.management_key,
        )
        return response.json()

    def update_display_name(
        self,
        login_id: str,
        display_name: Optional[str] = None,
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
            MgmtV1.user_update_name_path,
            {"loginId": login_id, "displayName": display_name},
            pswd=self._auth.management_key,
        )
        return response.json()

    def update_picture(
        self,
        login_id: str,
        picture: Optional[str] = None,
    ) -> dict:
        """
        Update the picture for an existing user.

        Args:
        login_id (str): The login ID of the user to update.
        picture (str): Optional url to user avatar. Leave empty to remove.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the update operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_update_picture_path,
            {"loginId": login_id, "picture": picture},
            pswd=self._auth.management_key,
        )
        return response.json()

    def update_custom_attribute(
        self, login_id: str, attribute_key: str, attribute_val: Union[str, int, bool]
    ) -> dict:
        """
        Update a custom attribute of an existing user.

        Args:
        login_id (str): The login ID of the user to update.
        attribute_key (str): The custom attribute that needs to be updated, this attribute needs to exists in Descope console app
        attribute_val: The value to be updated

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the update operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_update_custom_attribute_path,
            {
                "loginId": login_id,
                "attributeKey": attribute_key,
                "attributeValue": attribute_val,
            },
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
            MgmtV1.user_add_role_path,
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
            MgmtV1.user_remove_role_path,
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
            MgmtV1.user_add_tenant_path,
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
            MgmtV1.user_remove_tenant_path,
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
            MgmtV1.user_add_role_path,
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
            MgmtV1.user_remove_role_path,
            {"loginId": login_id, "tenantId": tenant_id, "roleNames": role_names},
            pswd=self._auth.management_key,
        )
        return response.json()

    def set_password(
        self,
        login_id: str,
        password: str,
    ) -> None:
        """
            Set the password for the given login ID.
            Note: The password will automatically be set as expired.
            The user will not be able to log-in with this password, and will be required to replace it on next login.
            See also: expire_password

        Args:
        login_id (str): The login ID of the user to set the password to.
        password (str): The new password to set to the user.

        Raise:
        AuthException: raised if the operation fails
        """
        self._auth.do_post(
            MgmtV1.user_set_password_path,
            {"loginId": login_id, "password": password},
            pswd=self._auth.management_key,
        )
        return

    def expire_password(
        self,
        login_id: str,
    ) -> None:
        """
            Expires the password for the given login ID.
            Note: user sign-in with an expired password, the user will get an error with code.
            Use the `password.send_reset` or `password.replace` methods to reset/replace the password.

        Args:
        login_id (str): The login ID of the user expire the password to.

        Raise:
        AuthException: raised if the operation fails
        """
        self._auth.do_post(
            MgmtV1.user_expire_password_path,
            {"loginId": login_id},
            pswd=self._auth.management_key,
        )
        return

    def generate_otp_for_test_user(
        self,
        method: DeliveryMethod,
        login_id: str,
    ) -> dict:
        """
        Generate OTP for the given login ID of a test user.
        This is useful when running tests and don't want to use 3rd party messaging services.

        Args:
        method (DeliveryMethod): The method to use for "delivering" the OTP verification code to the user, for example
            EMAIL, SMS, or WHATSAPP
        login_id (str): The login ID of the test user being validated.

        Return value (dict):
        Return dict in the format
             {"code": "", "loginId": ""}
        Containing the code for the login (exactly as it sent via Email or SMS).

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_generate_otp_for_test_path,
            {"loginId": login_id, "deliveryMethod": Auth.get_method_string(method)},
            pswd=self._auth.management_key,
        )
        return response.json()

    def generate_magic_link_for_test_user(
        self,
        method: DeliveryMethod,
        login_id: str,
        uri: str,
    ) -> dict:
        """
        Generate Magic Link for the given login ID of a test user.
        This is useful when running tests and don't want to use 3rd party messaging services.

        Args:
        method (DeliveryMethod): The method to use for "delivering" the verification magic link to the user, for example
            EMAIL, SMS, or WHATSAPP
        login_id (str): The login ID of the test user being validated.
        uri (str): Optional redirect uri which will be used instead of any global configuration.

        Return value (dict):
        Return dict in the format
             {"link": "", "loginId": ""}
        Containing the magic link for the login (exactly as it sent via Email or SMS).

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_generate_magic_link_for_test_path,
            {
                "loginId": login_id,
                "deliveryMethod": Auth.get_method_string(method),
                "URI": uri,
            },
            pswd=self._auth.management_key,
        )
        return response.json()

    def generate_enchanted_link_for_test_user(
        self,
        login_id: str,
        uri: str,
    ) -> dict:
        """
        Generate Enchanted Link for the given login ID of a test user.
        This is useful when running tests and don't want to use 3rd party messaging services.

        Args:
        login_id (str): The login ID of the test user being validated.
        uri (str): Optional redirect uri which will be used instead of any global configuration.

        Return value (dict):
        Return dict in the format
             {"link": "", "loginId": "", "pendingRef": ""}
        Containing the enchanted link for the login (exactly as it sent via Email or SMS) and pendingRef.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_generate_enchanted_link_for_test_path,
            {"loginId": login_id, "URI": uri},
            pswd=self._auth.management_key,
        )
        return response.json()

    def generate_embedded_link(
        self, login_id: str, custom_claims: Optional[dict] = None
    ) -> str:
        """
        Generate Embedded Link for the given user login ID.
        The return value is a token that can be verified via magic link, or using flows

        Args:
        login_id (str): The login ID of the user to authenticate with.
        custom_claims (dict): Additional claims to place on the jwt after verification

        Return value (str):
        Return the token to be used in verification process

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_generate_embedded_link_path,
            {"loginId": login_id, "customClaims": custom_claims},
            pswd=self._auth.management_key,
        )
        return response.json()["token"]

    @staticmethod
    def _compose_create_body(
        login_id: str,
        email: Optional[str],
        phone: Optional[str],
        display_name: Optional[str],
        role_names: List[str],
        user_tenants: List[AssociatedTenant],
        invite: bool,
        test: bool,
        picture: Optional[str],
        custom_attributes: Optional[dict],
        verified_email: Optional[bool],
        verified_phone: Optional[bool],
        invite_url: Optional[str],
    ) -> dict:
        body = User._compose_update_body(
            login_id,
            email,
            phone,
            display_name,
            role_names,
            user_tenants,
            test,
            picture,
            custom_attributes,
        )
        body["invite"] = invite
        if verified_email is not None:
            body["verifiedEmail"] = verified_email
        if verified_phone is not None:
            body["verifiedPhone"] = verified_phone
        if invite_url is not None:
            body["inviteUrl"] = invite_url
        return body

    @staticmethod
    def _compose_update_body(
        login_id: str,
        email: Optional[str],
        phone: Optional[str],
        display_name: Optional[str],
        role_names: List[str],
        user_tenants: List[AssociatedTenant],
        test: bool,
        picture: Optional[str],
        custom_attributes: Optional[dict],
        verified_email: Optional[bool] = None,
        verified_phone: Optional[bool] = None,
    ) -> dict:
        res = {
            "loginId": login_id,
            "email": email,
            "phone": phone,
            "displayName": display_name,
            "roleNames": role_names,
            "userTenants": associated_tenants_to_dict(user_tenants),
            "test": test,
            "picture": picture,
            "customAttributes": custom_attributes,
        }
        if verified_email is not None:
            res["verifiedEmail"] = verified_email
        if verified_phone is not None:
            res["verifiedPhone"] = verified_phone
        return res
