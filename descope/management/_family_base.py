from __future__ import annotations

from typing import Any, List, Optional


class FamilyBase:
    @staticmethod
    def _compose_create_body(
        name: str,
        id: Optional[str],
        custom_attributes: Optional[dict],
        photo: Optional[str],
        disabled: Optional[bool],
    ) -> dict:
        body: dict[str, Any] = {"name": name}
        if id is not None:
            body["familyId"] = id
        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes
        if photo is not None:
            body["photo"] = photo
        if disabled is not None:
            body["disabled"] = disabled
        return body

    @staticmethod
    def _compose_update_body(
        id: str,
        name: Optional[str],
        custom_attributes: Optional[dict],
        photo: Optional[str],
        disabled: Optional[bool],
    ) -> dict:
        body: dict[str, Any] = {"id": id}
        if name is not None:
            body["name"] = name
        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes
        if photo is not None:
            body["photo"] = photo
        if disabled is not None:
            body["disabled"] = disabled
        return body

    @staticmethod
    def _compose_search_body(
        ids: Optional[List[str]],
        names: Optional[List[str]],
        text: Optional[str],
        custom_attributes: Optional[dict],
        page: Optional[int],
        size: Optional[int],
    ) -> dict:
        body: dict[str, Any] = {}
        if ids is not None:
            body["familyIds"] = ids
        if names is not None:
            body["familyNames"] = names
        if text is not None:
            body["freeText"] = text
        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes
        if page is not None:
            body["page"] = page
        if size is not None:
            body["size"] = size
        return body

    @staticmethod
    def _compose_create_dependent_body(
        family_id: str,
        login_id: Optional[str],
        name: Optional[str],
        email: Optional[str],
        phone: Optional[str],
        given_name: Optional[str],
        middle_name: Optional[str],
        family_name: Optional[str],
        picture: Optional[str],
        custom_attributes: Optional[dict],
        family_scoped_attributes: Optional[dict],
    ) -> dict:
        body: dict[str, Any] = {"familyId": family_id}
        if login_id is not None:
            body["loginId"] = login_id
        if name is not None:
            body["name"] = name
        if email is not None:
            body["email"] = email
        if phone is not None:
            body["phone"] = phone
        if given_name is not None:
            body["givenName"] = given_name
        if middle_name is not None:
            body["middleName"] = middle_name
        if family_name is not None:
            body["familyName"] = family_name
        if picture is not None:
            body["picture"] = picture
        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes
        if family_scoped_attributes is not None:
            body["familyScopedAttributes"] = {family_id: family_scoped_attributes}
        return body

    @staticmethod
    def _compose_impersonate_body(
        impersonator_user_id_or_login_id: str,
        dependent_login_id: str,
        selected_family: Optional[str],
    ) -> dict:
        body: dict[str, Any] = {
            "impersonatorUserIdOrLoginId": impersonator_user_id_or_login_id,
            "dependentLoginId": dependent_login_id,
        }
        if selected_family is not None:
            body["selectedFamily"] = selected_family
        return body

    @staticmethod
    def _compose_stop_impersonation_body(
        jwt: str,
        custom_claims: Optional[dict],
        refresh_duration: Optional[int],
    ) -> dict:
        body: dict[str, Any] = {"jwt": jwt}
        if custom_claims is not None:
            body["customClaims"] = custom_claims
        if refresh_duration is not None:
            body["refreshDuration"] = refresh_duration
        return body

    @staticmethod
    def _compose_settings_body(
        enabled: Optional[bool],
        max_family_members: Optional[int],
        allow_multiple_families_users: Optional[bool],
    ) -> dict:
        body: dict[str, Any] = {}
        if enabled is not None:
            body["enabled"] = enabled
        if max_family_members is not None:
            body["maxFamilyMembers"] = max_family_members
        if allow_multiple_families_users is not None:
            body["allowMultipleFamiliesUsers"] = allow_multiple_families_users
        return body
