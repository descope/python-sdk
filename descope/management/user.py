from typing import Any, List, Optional, Union

from descope._http_base import HTTPBase
from descope.common import DeliveryMethod, LoginOptions, get_method_string
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.management.common import (
    AssociatedTenant,
    MgmtV1,
    Sort,
    associated_tenants_to_dict,
    sort_to_dict,
)
from descope.management.user_pwd import UserPassword


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
        password: Optional[UserPassword] = None,
        seed: Optional[str] = None,
        status: Optional[str] = None,
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
        self.password = password
        self.seed = seed
        self.status = status


class CreateUserObj:
    def __init__(
        self,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        name: Optional[str] = None,
        given_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        family_name: Optional[str] = None,
    ):
        self.email = email
        self.phone = phone
        self.name = name
        self.given_name = given_name
        self.middle_name = middle_name
        self.family_name = family_name


class User(HTTPBase):
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
        role_names = [] if role_names is None else role_names
        user_tenants = [] if user_tenants is None else user_tenants

        response = self._http.post(
            MgmtV1.user_create_path,
            body=User._compose_create_body(
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
        )
        return response

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
        role_names = [] if role_names is None else role_names
        user_tenants = [] if user_tenants is None else user_tenants

        response = self._http.post(
            MgmtV1.test_user_create_path,
            body=User._compose_create_body(
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
                sso_app_ids,
            ),
        )
        return response

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
        template_id: str = "",
        test: bool = False,
    ):
        role_names = [] if role_names is None else role_names
        user_tenants = [] if user_tenants is None else user_tenants
        
        response = self._http.post(
            MgmtV1.user_create_path,
            body=User._compose_create_body(
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
                test,
                picture,
                custom_attributes,
                verified_email,
                verified_phone,
                invite_url,
                send_mail,
                send_sms,
                additional_login_ids,
                sso_app_ids,
                template_id,
            ),
        )
        return response

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
        response = self._http.post(
            MgmtV1.user_create_batch_path,
            body=User._compose_create_batch_body(
                users,
                invite_url,
                send_mail,
                send_sms,
            ),
        )
        return response

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
        test: bool = False,
    ) -> dict:
        role_names = [] if role_names is None else role_names
        user_tenants = [] if user_tenants is None else user_tenants

        response = self._http.post(
            MgmtV1.user_update_path,
            body=User._compose_update_body(
                login_id,
                email,
                phone,
                display_name,
                given_name,
                middle_name,
                family_name,
                role_names,
                user_tenants,
                test,
                picture,
                custom_attributes,
                verified_email,
                verified_phone,
                additional_login_ids,
                sso_app_ids,
                None,
            ),
        )
        return response

    def patch(
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
        sso_app_ids: Optional[List[str]] = None,
        status: Optional[str] = None,
        test: bool = False,
    ) -> dict:
        if status is not None and status not in ["enabled", "disabled", "invited"]:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Invalid status value: {status}. Must be one of: enabled, disabled, invited",
            )
        response = self._http.patch(
            MgmtV1.user_patch_path,
            body=User._compose_patch_body(
                login_id,
                email,
                phone,
                display_name,
                given_name,
                middle_name,
                family_name,
                role_names,
                user_tenants,
                picture,
                custom_attributes,
                verified_email,
                verified_phone,
                sso_app_ids,
                status,
                test,
            ),
        )
        return response

    def patch_batch(
        self,
        users: List[UserObj],
        test: bool = False,
    ) -> dict:
        for user in users:
            if user.status is not None and user.status not in [
                "enabled",
                "disabled",
                "invited",
            ]:
                raise AuthException(
                    400,
                    ERROR_TYPE_INVALID_ARGUMENT,
                    f"Invalid status value: {user.status} for user {user.login_id}. Must be one of: enabled, disabled, invited",
                )

        response = self._http.patch(
            MgmtV1.user_patch_batch_path,
            body=User._compose_patch_batch_body(users, test),
        )
        return response

    def delete(
        self,
        login_id: str,
    ):
        self._http.post(
            MgmtV1.user_delete_path,
            body={"loginId": login_id},
        )

    def delete_by_user_id(
        self,
        user_id: str,
    ):
        self._http.post(
            MgmtV1.user_delete_path,
            body={"userId": user_id},
        )

    def delete_all_test_users(
        self,
    ):
        self._http.delete(
            MgmtV1.user_delete_all_test_users_path,
        )

    def load(
        self,
        login_id: str,
    ) -> dict:
        response = self._http.get(
            uri=MgmtV1.user_load_path,
            params={"loginId": login_id},
        )
        return response

    def load_by_user_id(
        self,
        user_id: str,
    ) -> dict:
        response = self._http.get(
            uri=MgmtV1.user_load_path,
            params={"userId": user_id},
        )
        return response

    def logout_user(
        self,
        login_id: str,
    ):
        self._http.post(
            MgmtV1.user_logout_path,
            body={"loginId": login_id},
        )

    def logout_user_by_user_id(
        self,
        user_id: str,
    ):
        self._http.post(
            MgmtV1.user_logout_path,
            body={"userId": user_id},
        )

    def load_users(
        self,
        user_ids: List[str],
        include_invalid_users: Optional[bool] = None,
    ) -> dict:
        if user_ids is None or len(user_ids) == 0:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "At least one user id needs to be supplied",
            )

        body: dict[str, Union[List[str], bool]] = {
            "userIds": user_ids,
        }

        if include_invalid_users is not None:
            body["includeInvalidUsers"] = include_invalid_users

        response = self._http.post(
            MgmtV1.users_load_path,
            body=body,
        )
        return response

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
        login_ids: Optional[List[str]] = None,
        from_created_time: Optional[int] = None,
        to_created_time: Optional[int] = None,
        from_modified_time: Optional[int] = None,
        to_modified_time: Optional[int] = None,
        user_ids: Optional[List[str]] = None,
        tenant_role_ids: Optional[dict] = None,
        tenant_role_names: Optional[dict] = None,
    ) -> dict:
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

        if login_ids is not None:
            body["loginIds"] = login_ids

        if user_ids is not None:
            body["userIds"] = user_ids

        if text is not None:
            body["text"] = text

        if sort is not None:
            body["sort"] = sort_to_dict(sort)

        if from_created_time is not None:
            body["fromCreatedTime"] = from_created_time
        if to_created_time is not None:
            body["toCreatedTime"] = to_created_time
        if from_modified_time is not None:
            body["fromModifiedTime"] = from_modified_time
        if to_modified_time is not None:
            body["toModifiedTime"] = to_modified_time

        if tenant_role_ids is not None:
            body["tenantRoleIds"] = tenant_role_ids
        if tenant_role_names is not None:
            body["tenantRoleNames"] = tenant_role_names

        response = self._http.post(
            MgmtV1.users_search_path,
            body=body,
        )
        return response

    def search_all_test_users(
        self,
        tenant_ids: Optional[List[str]] = None,
        role_names: Optional[List[str]] = None,
        limit: int = 0,
        page: int = 0,
        custom_attributes: Optional[dict] = None,
        statuses: Optional[List[str]] = None,
        emails: Optional[List[str]] = None,
        phones: Optional[List[str]] = None,
        sso_app_ids: Optional[List[str]] = None,
        sort: Optional[List[Sort]] = None,
        text: Optional[str] = None,
        login_ids: Optional[List[str]] = None,
        from_created_time: Optional[int] = None,
        to_created_time: Optional[int] = None,
        from_modified_time: Optional[int] = None,
        to_modified_time: Optional[int] = None,
        tenant_role_ids: Optional[dict] = None,
        tenant_role_names: Optional[dict] = None,
    ) -> dict:
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
            "testUsersOnly": True,
            "withTestUser": True,
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

        if login_ids is not None:
            body["loginIds"] = login_ids

        if text is not None:
            body["text"] = text

        if sort is not None:
            body["sort"] = sort_to_dict(sort)

        if from_created_time is not None:
            body["fromCreatedTime"] = from_created_time
        if to_created_time is not None:
            body["toCreatedTime"] = to_created_time
        if from_modified_time is not None:
            body["fromModifiedTime"] = from_modified_time
        if to_modified_time is not None:
            body["toModifiedTime"] = to_modified_time

        if tenant_role_ids is not None:
            body["tenantRoleIds"] = tenant_role_ids
        if tenant_role_names is not None:
            body["tenantRoleNames"] = tenant_role_names

        response = self._http.post(
            MgmtV1.test_users_search_path,
            body=body,
        )
        return response

    def get_provider_token(
        self,
        login_id: str,
        provider: str,
        withRefreshToken: Optional[bool] = False,
        forceRefresh: Optional[bool] = False,
    ) -> dict:
        response = self._http.get(
            MgmtV1.user_get_provider_token,
            params={
                "loginId": login_id,
                "provider": provider,
                "withRefreshToken": withRefreshToken,
                "forceRefresh": forceRefresh,
            },
        )
        return response

    def activate(
        self,
        login_id: str,
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_update_status_path,
            body={"loginId": login_id, "status": "enabled"},
        )
        return response

    def deactivate(
        self,
        login_id: str,
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_update_status_path,
            body={"loginId": login_id, "status": "disabled"},
        )
        return response

    def update_login_id(
        self,
        login_id: str,
        new_login_id: Optional[str] = None,
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_update_login_id_path,
            body={"loginId": login_id, "newLoginId": new_login_id},
        )
        return response

    def update_email(
        self,
        login_id: str,
        email: Optional[str] = None,
        verified: Optional[bool] = None,
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_update_email_path,
            body={"loginId": login_id, "email": email, "verified": verified},
        )
        return response

    def update_phone(
        self,
        login_id: str,
        phone: Optional[str] = None,
        verified: Optional[bool] = None,
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_update_phone_path,
            body={"loginId": login_id, "phone": phone, "verified": verified},
        )
        return response

    def update_display_name(
        self,
        login_id: str,
        display_name: Optional[str] = None,
        given_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        family_name: Optional[str] = None,
    ) -> dict:
        bdy = {"loginId": login_id}
        if display_name is not None:
            bdy["displayName"] = display_name
        if given_name is not None:
            bdy["givenName"] = given_name
        if middle_name is not None:
            bdy["middleName"] = middle_name
        if family_name is not None:
            bdy["familyName"] = family_name
        response = self._http.post(
            MgmtV1.user_update_name_path,
            body=bdy,
        )
        return response

    def update_picture(
        self,
        login_id: str,
        picture: Optional[str] = None,
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_update_picture_path,
            body={"loginId": login_id, "picture": picture},
        )
        return response

    def update_custom_attribute(
        self, login_id: str, attribute_key: str, attribute_val: Union[str, int, bool]
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_update_custom_attribute_path,
            body={
                "loginId": login_id,
                "attributeKey": attribute_key,
                "attributeValue": attribute_val,
            },
        )
        return response

    def set_roles(
        self,
        login_id: str,
        role_names: List[str],
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_set_role_path,
            body={"loginId": login_id, "roleNames": role_names},
        )
        return response

    def add_roles(
        self,
        login_id: str,
        role_names: List[str],
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_add_role_path,
            body={"loginId": login_id, "roleNames": role_names},
        )
        return response

    def remove_roles(
        self,
        login_id: str,
        role_names: List[str],
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_remove_role_path,
            body={"loginId": login_id, "roleNames": role_names},
        )
        return response

    def set_sso_apps(
        self,
        login_id: str,
        sso_app_ids: List[str],
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_set_sso_apps,
            body={"loginId": login_id, "ssoAppIds": sso_app_ids},
        )
        return response

    def add_sso_apps(
        self,
        login_id: str,
        sso_app_ids: List[str],
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_add_sso_apps,
            body={"loginId": login_id, "ssoAppIds": sso_app_ids},
        )
        return response

    def remove_sso_apps(
        self,
        login_id: str,
        sso_app_ids: List[str],
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_remove_sso_apps,
            body={"loginId": login_id, "ssoAppIds": sso_app_ids},
        )
        return response

    def add_tenant(
        self,
        login_id: str,
        tenant_id: str,
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_add_tenant_path,
            body={"loginId": login_id, "tenantId": tenant_id},
        )
        return response

    def remove_tenant(
        self,
        login_id: str,
        tenant_id: str,
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_remove_tenant_path,
            body={"loginId": login_id, "tenantId": tenant_id},
        )
        return response

    def set_tenant_roles(
        self,
        login_id: str,
        tenant_id: str,
        role_names: List[str],
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_set_role_path,
            body={"loginId": login_id, "tenantId": tenant_id, "roleNames": role_names},
        )
        return response

    def add_tenant_roles(
        self,
        login_id: str,
        tenant_id: str,
        role_names: List[str],
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_add_role_path,
            body={"loginId": login_id, "tenantId": tenant_id, "roleNames": role_names},
        )
        return response

    def remove_tenant_roles(
        self,
        login_id: str,
        tenant_id: str,
        role_names: List[str],
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_remove_role_path,
            body={"loginId": login_id, "tenantId": tenant_id, "roleNames": role_names},
        )
        return response

    def set_temporary_password(
        self,
        login_id: str,
        password: str,
    ) -> None:
        self._http.post(
            MgmtV1.user_set_temporary_password_path,
            body={
                "loginId": login_id,
                "password": password,
                "setActive": False,
            },
        )
        return

    def set_active_password(
        self,
        login_id: str,
        password: str,
    ) -> None:
        self._http.post(
            MgmtV1.user_set_active_password_path,
            body={
                "loginId": login_id,
                "password": password,
                "setActive": True,
            },
        )
        return

    def set_password(
        self,
        login_id: str,
        password: str,
        set_active: Optional[bool] = False,
    ) -> None:
        self._http.post(
            MgmtV1.user_set_password_path,
            body={
                "loginId": login_id,
                "password": password,
                "setActive": set_active,
            },
        )
        return

    def expire_password(
        self,
        login_id: str,
    ) -> None:
        self._http.post(
            MgmtV1.user_expire_password_path,
            body={"loginId": login_id},
        )
        return

    def remove_all_passkeys(
        self,
        login_id: str,
    ) -> None:
        self._http.post(
            MgmtV1.user_remove_all_passkeys_path,
            body={"loginId": login_id},
        )
        return

    def remove_totp_seed(
        self,
        login_id: str,
    ) -> None:
        self._http.post(
            MgmtV1.user_remove_totp_seed_path,
            body={"loginId": login_id},
        )
        return

    def generate_otp_for_test_user(
        self,
        method: DeliveryMethod,
        login_id: str,
        login_options: Optional[LoginOptions] = None,
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_generate_otp_for_test_path,
            body={
                "loginId": login_id,
                "deliveryMethod": get_method_string(method),
                "loginOptions": login_options.__dict__ if login_options else {},
            },
        )
        return response

    def generate_magic_link_for_test_user(
        self,
        method: DeliveryMethod,
        login_id: str,
        uri: str,
        login_options: Optional[LoginOptions] = None,
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_generate_magic_link_for_test_path,
            body={
                "loginId": login_id,
                "deliveryMethod": get_method_string(method),
                "URI": uri,
                "loginOptions": login_options.__dict__ if login_options else {},
            },
        )
        return response

    def generate_enchanted_link_for_test_user(
        self,
        login_id: str,
        uri: str,
        login_options: Optional[LoginOptions] = None,
    ) -> dict:
        response = self._http.post(
            MgmtV1.user_generate_enchanted_link_for_test_path,
            body={
                "loginId": login_id,
                "URI": uri,
                "loginOptions": login_options.__dict__ if login_options else {},
            },
        )
        return response

    def generate_embedded_link(
        self, login_id: str, custom_claims: Optional[dict] = None, timeout: int = 0
    ) -> str:
        response = self._http.post(
            MgmtV1.user_generate_embedded_link_path,
            body={
                "loginId": login_id,
                "customClaims": custom_claims,
                "timeout": timeout,
            },
        )
        return response.json()["token"]

    def generate_sign_up_embedded_link(
        self,
        login_id: str,
        user: Optional[CreateUserObj] = None,
        email_verified: bool = False,
        phone_verified: bool = False,
        login_options: Optional[LoginOptions] = None,
        timeout: int = 0,
    ) -> str:
        response = self._http.post(
            MgmtV1.user_generate_sign_up_embedded_link_path,
            body={
                "loginId": login_id,
                "user": user.__dict__ if user else {},
                "loginOptions": login_options.__dict__ if login_options else {},
                "emailVerified": email_verified,
                "phoneVerified": phone_verified,
                "timeout": timeout,
            },
        )
        return response.json()["token"]

    def history(self, user_ids: List[str]) -> List[dict]:
        response = self._http.post(
            MgmtV1.user_history_path,
            body=user_ids,
        )
        return response

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
        template_id: str = "",
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
        if template_id != "":
            body["templateId"] = template_id
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
            password = None if user.password is None else user.password.cleartext
            hashed_password = None
            if (user.password is not None) and (user.password.hashed is not None):
                hashed_password = user.password.hashed.to_dict()
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
                password=password,
                hashed_password=hashed_password,
                seed=user.seed,
            )
            if user.status is not None:
                uBody["status"] = user.status
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
        password: Optional[str] = None,
        hashed_password: Optional[dict] = None,
        seed: Optional[str] = None,
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
        if password is not None:
            res["password"] = password
        if hashed_password is not None:
            res["hashedPassword"] = hashed_password
        if seed is not None:
            res["seed"] = seed
        return res

    @staticmethod
    def _compose_patch_body(
        login_id: str,
        email: Optional[str],
        phone: Optional[str],
        display_name: Optional[str],
        given_name: Optional[str],
        middle_name: Optional[str],
        family_name: Optional[str],
        role_names: Optional[List[str]],
        user_tenants: Optional[List[AssociatedTenant]],
        picture: Optional[str],
        custom_attributes: Optional[dict],
        verified_email: Optional[bool],
        verified_phone: Optional[bool],
        sso_app_ids: Optional[List[str]],
        status: Optional[str],
        test: bool = False,
    ) -> dict:
        res: dict[str, Any] = {
            "loginId": login_id,
        }
        if email is not None:
            res["email"] = email
        if phone is not None:
            res["phone"] = phone
        if display_name is not None:
            res["displayName"] = display_name
        if given_name is not None:
            res["givenName"] = given_name
        if middle_name is not None:
            res["middleName"] = middle_name
        if family_name is not None:
            res["familyName"] = family_name
        if role_names is not None:
            res["roleNames"] = role_names
        if user_tenants is not None:
            res["userTenants"] = associated_tenants_to_dict(user_tenants)
        if picture is not None:
            res["picture"] = picture
        if custom_attributes is not None:
            res["customAttributes"] = custom_attributes
        if verified_email is not None:
            res["verifiedEmail"] = verified_email
        if verified_phone is not None:
            res["verifiedPhone"] = verified_phone
        if sso_app_ids is not None:
            res["ssoAppIds"] = sso_app_ids
        if status is not None:
            res["status"] = status
        if test:
            res["test"] = test
        return res

    @staticmethod
    def _compose_patch_batch_body(
        users: List[UserObj],
        test: bool = False,
    ) -> dict:
        users_body = []
        for user in users:
            user_body = User._compose_patch_body(
                login_id=user.login_id,
                email=user.email,
                phone=user.phone,
                display_name=user.display_name,
                given_name=user.given_name,
                middle_name=user.middle_name,
                family_name=user.family_name,
                role_names=user.role_names,
                user_tenants=user.user_tenants,
                picture=user.picture,
                custom_attributes=user.custom_attributes,
                verified_email=user.verified_email,
                verified_phone=user.verified_phone,
                sso_app_ids=user.sso_app_ids,
                status=user.status,
                test=test,
            )
            users_body.append(user_body)

        return {"users": users_body}
