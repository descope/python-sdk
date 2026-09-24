from __future__ import annotations

from typing import Any, List, Optional


class FamilyBase:
    @staticmethod
    def _compose_create_body(
        name: str,
        custom_attributes: Optional[dict],
        photo: Optional[str],
        disabled: Optional[bool],
        family_id: Optional[str],
    ) -> dict:
        body: dict[str, Any] = {"name": name}
        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes
        if photo is not None:
            body["photo"] = photo
        if disabled is not None:
            body["disabled"] = disabled
        if family_id is not None:
            body["familyId"] = family_id
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
        family_ids: Optional[List[str]],
        free_text: Optional[str],
        family_names: Optional[List[str]],
        page: Optional[int],
        size: Optional[int],
        custom_attributes: Optional[dict],
    ) -> dict:
        body: dict[str, Any] = {}
        if family_ids is not None:
            body["familyIds"] = family_ids
        if free_text is not None:
            body["freeText"] = free_text
        if family_names is not None:
            body["familyNames"] = family_names
        if page is not None:
            body["page"] = page
        if size is not None:
            body["size"] = size
        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes
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
        optional_fields = {
            "loginId": login_id,
            "name": name,
            "email": email,
            "phone": phone,
            "givenName": given_name,
            "middleName": middle_name,
            "familyName": family_name,
            "picture": picture,
            "customAttributes": custom_attributes,
            "familyScopedAttributes": family_scoped_attributes,
        }
        body.update({k: v for k, v in optional_fields.items() if v is not None})
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
