from __future__ import annotations

from typing import Any, List, Optional

from descope.common import DeliveryMethod, LoginOptions, get_method_string
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.management.common import (
    AssociatedTenant,
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


class UserBase:
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
        locale: Optional[str] = None,
    ) -> dict:
        body = UserBase._compose_update_body(
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
        if locale is not None:
            body["locale"] = locale
        return body

    @staticmethod
    def _compose_create_batch_body(
        users: List[UserObj],
        invite_url: Optional[str],
        send_mail: Optional[bool],
        send_sms: Optional[bool],
        locale: Optional[str] = None,
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
            uBody = UserBase._compose_update_body(
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
        if locale is not None:
            body["locale"] = locale
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
            user_body = UserBase._compose_patch_body(
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

    @staticmethod
    def _validate_search_pagination(limit: int, page: int) -> None:
        if limit < 0:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "limit must be non-negative")
        if page < 0:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "page must be non-negative")
