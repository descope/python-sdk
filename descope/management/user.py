from typing import List, Optional, Union

from descope._auth_base import AuthBase
from descope.auth import Auth
from descope.common import DeliveryMethod, LoginOptions
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.management.common import (
    AssociatedTenant,
    MgmtV1,
    Sort,
    associated_tenants_to_dict,
    sort_to_dict,
)


class UserObj:
    def __init__(
        self,
        login_id: str,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        display_name: Optional[str] = None,
        given_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        family_name: Optional[str] = None,
        role_names: Optional[List[str]] = None,
        user_tenants: Optional[List[AssociatedTenant]] = None,
        picture: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
        verified_email: Optional[bool] = None,
        verified_phone: Optional[bool] = None,
        additional_login_ids: Optional[List[str]] = None,
        sso_app_ids: Optional[List[str]] = None,
    ):
        self.login_id = login_id
        self.email = email
        self.phone = phone
        self.display_name = display_name
        self.given_name = given_name
        self.middle_name = middle_name
        self.family_name = family_name
        self.role_names = role_names
        self.user_tenants = user_tenants
        self.picture = picture
        self.custom_attributes = custom_attributes
        self.verified_email = verified_email
        self.verified_phone = verified_phone
        self.additional_login_ids = additional_login_ids
        self.sso_app_ids = sso_app_ids


class User(AuthBase):
    def create(
        self,
        login_id: str,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        display_name: Optional[str] = None,
        given_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        family_name: Optional[str] = None,
        role_names: Optional[List[str]] = None,
        user_tenants: Optional[List[AssociatedTenant]] = None,
        picture: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
        verified_email: Optional[bool] = None,
        verified_phone: Optional[bool] = None,
        invite_url: Optional[str] = None,
        additional_login_ids: Optional[List[str]] = None,
        sso_app_ids: Optional[List[str]] = None,
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
        sso_app_ids (List[str]): Optional, list of SSO applications IDs to be associated with the user.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the created user information.

        Raise:
        AuthException: raised if create operation fails
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
                given_name,
                middle_name,
                family_name,
                role_names,
                user_tenants,
                False,
                False,
                picture,
                custom_attributes,
                verified_email,
                verified_phone,
                invite_url,
                None,
                None,
                additional_login_ids,
                sso_app_ids,
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
        given_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        family_name: Optional[str] = None,
        role_names: Optional[List[str]] = None,
        user_tenants: Optional[List[AssociatedTenant]] = None,
        picture: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
        verified_email: Optional[bool] = None,
        verified_phone: Optional[bool] = None,
        invite_url: Optional[str] = None,
        additional_login_ids: Optional[List[str]] = None,
        sso_app_ids: Optional[List[str]] = None,
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
        sso_app_ids (List[str]): Optional, list of SSO applications IDs to be associated with the user.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the created test user information.

        Raise:
        AuthException: raised if create operation fails
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
                given_name,
                middle_name,
                family_name,
                role_names,
                user_tenants,
                False,
                True,
                picture,
                custom_attributes,
                verified_email,
                verified_phone,
                invite_url,
                None,
                None,
                additional_login_ids,
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
        given_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        family_name: Optional[str] = None,
        role_names: Optional[List[str]] = None,
        user_tenants: Optional[List[AssociatedTenant]] = None,
        picture: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
        verified_email: Optional[bool] = None,
        verified_phone: Optional[bool] = None,
        invite_url: Optional[str] = None,
        send_mail: Optional[
            bool
        ] = None,  # send invite via mail, default is according to project settings
        send_sms: Optional[
            bool
        ] = None,  # send invite via text message, default is according to project settings
        additional_login_ids: Optional[List[str]] = None,
        sso_app_ids: Optional[List[str]] = None,
    ) -> dict:
        """
        Create a new user and invite them via an email / text message.

        Functions exactly the same as the `create` function with the additional invitation
            behavior. See the documentation above for the general creation behavior.

        IMPORTANT: Since the invitation is sent by email / phone, make sure either
            the email / phone is explicitly set, or the login_id itself is an email address / phone number.
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
                given_name,
                middle_name,
                family_name,
                role_names,
                user_tenants,
                True,
                False,
                picture,
                custom_attributes,
                verified_email,
                verified_phone,
                invite_url,
                send_mail,
                send_sms,
                additional_login_ids,
                sso_app_ids,
            ),
            pswd=self._auth.management_key,
        )
        return response.json()

    def invite_batch(
        self,
        users: List[UserObj],
        invite_url: Optional[str] = None,
        send_mail: Optional[
            bool
        ] = None,  # send invite via mail, default is according to project settings
        send_sms: Optional[
            bool
        ] = None,  # send invite via text message, default is according to project settings
    ) -> dict:
        """
        Create users in batch and invite them via an email / text message.

        Functions exactly the same as the `create` function with the additional invitation
            behavior. See the documentation above for the general creation behavior.

        IMPORTANT: Since the invitation is sent by email / phone, make sure either
            the email / phone is explicitly set, or the login_id itself is an email address / phone number.
            You must configure the invitation URL in the Descope console prior to
            calling the method.
        """

        response = self._auth.do_post(
            MgmtV1.user_create_batch_path,
            User._compose_create_batch_body(
                users,
                invite_url,
                send_mail,
                send_sms,
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
        given_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        family_name: Optional[str] = None,
        role_names: Optional[List[str]] = None,
        user_tenants: Optional[List[AssociatedTenant]] = None,
        picture: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
        verified_email: Optional[bool] = None,
        verified_phone: Optional[bool] = None,
        additional_login_ids: Optional[List[str]] = None,
        sso_app_ids: Optional[List[str]] = None,
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
        sso_app_ids (List[str]): Optional, list of SSO applications IDs to be associated with the user.

        Raise:
        AuthException: raised if update operation fails
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
                given_name,
                middle_name,
                family_name,
                role_names,
                user_tenants,
                False,
                picture,
                custom_attributes,
                verified_email,
                verified_phone,
                additional_login_ids,
                sso_app_ids,
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
        AuthException: raised if delete operation fails
        """
        self._auth.do_post(
            MgmtV1.user_delete_path,
            {"loginId": login_id},
            pswd=self._auth.management_key,
        )

    def delete_by_user_id(
        self,
        user_id: str,
    ):
        """
        Delete an existing user by user ID. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        user_id (str): The user ID from the user's JWT.

        Raise:
        AuthException: raised if delete operation fails
        """
        self._auth.do_post(
            MgmtV1.user_delete_path,
            {"userId": user_id},
            pswd=self._auth.management_key,
        )

    def delete_all_test_users(
        self,
    ):
        """
        Delete all test users in the project. IMPORTANT: This action is irreversible. Use carefully.

        Raise:
        AuthException: raised if delete operation fails
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

    def logout_user(
        self,
        login_id: str,
    ):
        """
        Logout a user from all devices.

        Args:
        login_id (str): The login ID of the user to be logged out.

        Raise:
        AuthException: raised if logout operation fails
        """
        self._auth.do_post(
            MgmtV1.user_logout_path,
            {"loginId": login_id},
            pswd=self._auth.management_key,
        )

    def logout_user_by_user_id(
        self,
        user_id: str,
    ):
        """
        Logout a user from all devices.

        Args:
        user_id (str): The login ID of the user to be logged out.

        Raise:
        AuthException: raised if logout operation fails
        """
        self._auth.do_post(
            MgmtV1.user_logout_path,
            {"userId": user_id},
            pswd=self._auth.management_key,
        )

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
        emails: Optional[List[str]] = None,
        phones: Optional[List[str]] = None,
        sso_app_ids: Optional[List[str]] = None,
        sort: Optional[List[Sort]] = None,
        text: Optional[str] = None,
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
        custom_attributes (dict): Optional search for a attribute with a given value
        statuses (List[str]): Optional list of statuses to search for ("enabled", "disabled", "invited")
        emails (List[str]): Optional list of emails to search for
        phones (List[str]): Optional list of phones to search for
        sso_app_ids (List[str]): Optional list of SSO application IDs to filter by
        text (str): Optional string, allows free text search among all user's attributes.
        sort (List[Sort]): Optional List[dict], allows to sort by fields.

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

        if emails is not None:
            body["emails"] = emails

        if phones is not None:
            body["phones"] = phones

        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes

        if sso_app_ids is not None:
            body["ssoAppIds"] = sso_app_ids

        if text is not None:
            body["text"] = text

        if sort is not None:
            body["sort"] = sort_to_dict(sort)

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
        given_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        family_name: Optional[str] = None,
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
        bdy = {"loginId": login_id}
        if display_name is not None:
            bdy["displayName"] = display_name
        if given_name is not None:
            bdy["givenName"] = given_name
        if middle_name is not None:
            bdy["middleName"] = middle_name
        if family_name is not None:
            bdy["familyName"] = family_name
        response = self._auth.do_post(
            MgmtV1.user_update_name_path,
            bdy,
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

    def set_roles(
        self,
        login_id: str,
        role_names: List[str],
    ) -> dict:
        """
        Set roles to a user without tenant association. Use set_tenant_roles
        for users that are part of a multi-tenant project.

        Args:
        login_id (str): The login ID of the user to update.
        role_names (List[str]): A list of roles to set to a user without tenant association.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_set_role_path,
            {"loginId": login_id, "roleNames": role_names},
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

    def set_sso_apps(
        self,
        login_id: str,
        sso_app_ids: List[str],
    ) -> dict:
        """
        Set SSO applications association to a user.

        Args:
        login_id (str): The login ID of the user to update.
        sso_app_ids (List[str]): A list of sso applications ids for associate with a user.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_set_sso_apps,
            {"loginId": login_id, "ssoAppIds": sso_app_ids},
            pswd=self._auth.management_key,
        )
        return response.json()

    def add_sso_apps(
        self,
        login_id: str,
        sso_app_ids: List[str],
    ) -> dict:
        """
        Add SSO applications association to a user.

        Args:
        login_id (str): The login ID of the user to update.
        sso_app_ids (List[str]): A list of sso applications ids for associate with a user.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_add_sso_apps,
            {"loginId": login_id, "ssoAppIds": sso_app_ids},
            pswd=self._auth.management_key,
        )
        return response.json()

    def remove_sso_apps(
        self,
        login_id: str,
        sso_app_ids: List[str],
    ) -> dict:
        """
        Remove SSO applications association from a user.

        Args:
        login_id (str): The login ID of the user to update.
        sso_app_ids (List[str]): A list of sso applications ids to remove association from a user.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_remove_sso_apps,
            {"loginId": login_id, "ssoAppIds": sso_app_ids},
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

    def set_tenant_roles(
        self,
        login_id: str,
        tenant_id: str,
        role_names: List[str],
    ) -> dict:
        """
        Set roles to a user in a specific tenant.

        Args:
        login_id (str): The login ID of the user to update.
        tenant_id (str): The ID of the user's tenant.
        role_names (List[str]): A list of roles to set on the user.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the updated user information.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_set_role_path,
            {"loginId": login_id, "tenantId": tenant_id, "roleNames": role_names},
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
        login_id (str): The login ID of the user to expire the password to.

        Raise:
        AuthException: raised if the operation fails
        """
        self._auth.do_post(
            MgmtV1.user_expire_password_path,
            {"loginId": login_id},
            pswd=self._auth.management_key,
        )
        return

    def remove_all_passkeys(
        self,
        login_id: str,
    ) -> None:
        """
            Removes all registered passkeys (WebAuthn devices) for the user with the given login ID.
            Note: The user might not be able to login anymore if they have no other authentication
            methods or a verified email/phone.

        Args:
        login_id (str): The login ID of the user to remove passkeys for.

        Raise:
        AuthException: raised if the operation fails
        """
        self._auth.do_post(
            MgmtV1.user_remove_all_passkeys_path,
            {"loginId": login_id},
            pswd=self._auth.management_key,
        )
        return

    def generate_otp_for_test_user(
        self,
        method: DeliveryMethod,
        login_id: str,
        login_options: Optional[LoginOptions] = None,
    ) -> dict:
        """
        Generate OTP for the given login ID of a test user.
        This is useful when running tests and don't want to use 3rd party messaging services.

        Args:
        method (DeliveryMethod): The method to use for "delivering" the OTP verification code to the user, for example
            EMAIL, SMS, WHATSAPP or EMBEDDED
        login_id (str): The login ID of the test user being validated.
        login_options (LoginOptions): optional, can be provided to set custom claims to the generated jwt.

        Return value (dict):
        Return dict in the format
             {"code": "", "loginId": ""}
        Containing the code for the login (exactly as it sent via Email or SMS).

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_generate_otp_for_test_path,
            {
                "loginId": login_id,
                "deliveryMethod": Auth.get_method_string(method),
                "loginOptions": login_options.__dict__ if login_options else {},
            },
            pswd=self._auth.management_key,
        )
        return response.json()

    def generate_magic_link_for_test_user(
        self,
        method: DeliveryMethod,
        login_id: str,
        uri: str,
        login_options: Optional[LoginOptions] = None,
    ) -> dict:
        """
        Generate Magic Link for the given login ID of a test user.
        This is useful when running tests and don't want to use 3rd party messaging services.

        Args:
        method (DeliveryMethod): The method to use for "delivering" the verification magic link to the user, for example
            EMAIL, SMS, WHATSAPP or EMBEDDED
        login_id (str): The login ID of the test user being validated.
        uri (str): Optional redirect uri which will be used instead of any global configuration.
        login_options (LoginOptions): optional, can be provided to set custom claims to the generated jwt.

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
                "loginOptions": login_options.__dict__ if login_options else {},
            },
            pswd=self._auth.management_key,
        )
        return response.json()

    def generate_enchanted_link_for_test_user(
        self,
        login_id: str,
        uri: str,
        login_options: Optional[LoginOptions] = None,
    ) -> dict:
        """
        Generate Enchanted Link for the given login ID of a test user.
        This is useful when running tests and don't want to use 3rd party messaging services.

        Args:
        login_id (str): The login ID of the test user being validated.
        uri (str): Optional redirect uri which will be used instead of any global configuration.
        login_options (LoginOptions): optional, can be provided to set custom claims to the generated jwt.

        Return value (dict):
        Return dict in the format
             {"link": "", "loginId": "", "pendingRef": ""}
        Containing the enchanted link for the login (exactly as it sent via Email or SMS) and pendingRef.

        Raise:
        AuthException: raised if the operation fails
        """
        response = self._auth.do_post(
            MgmtV1.user_generate_enchanted_link_for_test_path,
            {
                "loginId": login_id,
                "URI": uri,
                "loginOptions": login_options.__dict__ if login_options else {},
            },
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
        given_name: Optional[str],
        middle_name: Optional[str],
        family_name: Optional[str],
        role_names: List[str],
        user_tenants: List[AssociatedTenant],
        invite: bool,
        test: bool,
        picture: Optional[str],
        custom_attributes: Optional[dict],
        verified_email: Optional[bool],
        verified_phone: Optional[bool],
        invite_url: Optional[str],
        send_mail: Optional[bool],
        send_sms: Optional[bool],
        additional_login_ids: Optional[List[str]],
        sso_app_ids: Optional[List[str]] = None,
    ) -> dict:
        body = User._compose_update_body(
            login_id=login_id,
            email=email,
            phone=phone,
            display_name=display_name,
            given_name=given_name,
            middle_name=middle_name,
            family_name=family_name,
            role_names=role_names,
            user_tenants=user_tenants,
            test=test,
            picture=picture,
            custom_attributes=custom_attributes,
            additional_login_ids=additional_login_ids,
            sso_app_ids=sso_app_ids,
        )
        body["invite"] = invite
        if verified_email is not None:
            body["verifiedEmail"] = verified_email
        if verified_phone is not None:
            body["verifiedPhone"] = verified_phone
        if invite_url is not None:
            body["inviteUrl"] = invite_url
        if send_mail is not None:
            body["sendMail"] = send_mail
        if send_sms is not None:
            body["sendSMS"] = send_sms
        return body

    @staticmethod
    def _compose_create_batch_body(
        users: List[UserObj],
        invite_url: Optional[str],
        send_mail: Optional[bool],
        send_sms: Optional[bool],
    ) -> dict:
        usersBody = []
        for user in users:
            role_names = [] if user.role_names is None else user.role_names
            user_tenants = [] if user.user_tenants is None else user.user_tenants
            sso_app_ids = [] if user.sso_app_ids is None else user.sso_app_ids
            uBody = User._compose_update_body(
                login_id=user.login_id,
                email=user.email,
                phone=user.phone,
                display_name=user.display_name,
                given_name=user.given_name,
                middle_name=user.middle_name,
                family_name=user.family_name,
                role_names=role_names,
                user_tenants=user_tenants,
                picture=user.picture,
                custom_attributes=user.custom_attributes,
                additional_login_ids=user.additional_login_ids,
                verified_email=user.verified_email,
                verified_phone=user.verified_phone,
                test=False,
                sso_app_ids=sso_app_ids,
            )
            usersBody.append(uBody)

        body = {"users": usersBody, "invite": True}
        if invite_url is not None:
            body["inviteUrl"] = invite_url
        if send_mail is not None:
            body["sendMail"] = send_mail
        if send_sms is not None:
            body["sendSMS"] = send_sms
        return body

    @staticmethod
    def _compose_update_body(
        login_id: str,
        email: Optional[str],
        phone: Optional[str],
        display_name: Optional[str],
        given_name: Optional[str],
        middle_name: Optional[str],
        family_name: Optional[str],
        role_names: List[str],
        user_tenants: List[AssociatedTenant],
        test: bool,
        picture: Optional[str],
        custom_attributes: Optional[dict],
        verified_email: Optional[bool] = None,
        verified_phone: Optional[bool] = None,
        additional_login_ids: Optional[List[str]] = None,
        sso_app_ids: Optional[List[str]] = None,
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
            "additionalLoginIds": additional_login_ids,
            "ssoAppIDs": sso_app_ids,
        }
        if verified_email is not None:
            res["verifiedEmail"] = verified_email
        if given_name is not None:
            res["givenName"] = given_name
        if middle_name is not None:
            res["middleName"] = middle_name
        if family_name is not None:
            res["familyName"] = family_name
        if verified_phone is not None:
            res["verifiedPhone"] = verified_phone
        return res
