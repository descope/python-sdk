from __future__ import annotations

from typing import List, Optional

from descope._http_base import AsyncHTTPBase
from descope.management._family_base import FamilyBase
from descope.management.common import (
    CustomAttribute,
    MgmtV1,
    custom_attributes_to_dict,
)


class FamilyAsync(FamilyBase, AsyncHTTPBase):
    """Async counterpart of Family - all HTTP calls are coroutines."""

    async def create(
        self,
        name: str,
        custom_attributes: Optional[dict] = None,
        photo: Optional[str] = None,
        disabled: Optional[bool] = None,
        family_id: Optional[str] = None,
    ) -> dict:
        """
        Create a new family with the given name. Family IDs are provisioned automatically, but can be
        provided explicitly if needed.

        Args:
        name (str): The family's name.
        custom_attributes (dict): Optional, the family's custom attribute values, keyed by attribute name.
            The attributes must first be defined with `create_custom_attributes`.
        photo (str): Optional URL of the family's photo.
        disabled (bool): Optional, whether the family is disabled.
        family_id (str): Optional family ID. A random ID is generated when omitted.

        Return value (dict):
        Return dict in the format
             {"family": {"id": <id>, "name": <name>, "customAttributes": {}, "disabled": <bool>, "photo": <url>, "createdTime": <timestamp>}}

        Raise:
        AuthException: raised if create operation fails
        """
        response = await self._http.post(
            MgmtV1.family_create_path,
            body=FamilyBase._compose_create_body(name, custom_attributes, photo, disabled, family_id),
        )
        return response.json()

    async def update(
        self,
        id: str,
        name: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
        photo: Optional[str] = None,
        disabled: Optional[bool] = None,
    ) -> dict:
        """
        Update an existing family. Only the given fields are updated; omitted fields are left unchanged.

        Args:
        id (str): The ID of the family to update.
        name (str): Optional updated family name.
        custom_attributes (dict): Optional, the family's custom attribute values, keyed by attribute name.
        photo (str): Optional URL of the family's photo.
        disabled (bool): Optional, whether the family is disabled.

        Return value (dict):
        Return dict in the format
             {"family": {...}}
        Containing the updated family information.

        Raise:
        AuthException: raised if update operation fails
        """
        response = await self._http.post(
            MgmtV1.family_update_path,
            body=FamilyBase._compose_update_body(id, name, custom_attributes, photo, disabled),
        )
        return response.json()

    async def delete(self, id: str) -> None:
        """
        Delete an existing family. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        id (str): The ID of the family to delete.

        Raise:
        AuthException: raised if delete operation fails
        """
        await self._http.post(MgmtV1.family_delete_path, body={"id": id})

    async def search(
        self,
        family_ids: Optional[List[str]] = None,
        free_text: Optional[str] = None,
        family_names: Optional[List[str]] = None,
        page: Optional[int] = None,
        size: Optional[int] = None,
        custom_attributes: Optional[dict] = None,
    ) -> dict:
        """
        Search families. Called with no arguments, returns all families.

        Args:
        family_ids (List[str]): Optional list of family IDs to filter by.
        free_text (str): Optional free text search among the families' attributes.
        family_names (List[str]): Optional list of family names to filter by.
        page (int): Optional pagination control. Pages start at 0.
        size (int): Optional page size (up to 1000).
        custom_attributes (dict): Optional, search for families with the given custom attribute values.

        Return value (dict):
        Return dict in the format
             {"families": [{...}]}
        Containing the found families.

        Raise:
        AuthException: raised if search operation fails
        """
        response = await self._http.post(
            MgmtV1.family_search_path,
            body=FamilyBase._compose_search_body(family_ids, free_text, family_names, page, size, custom_attributes),
        )
        return response.json()

    async def create_dependent(
        self,
        family_id: str,
        login_id: Optional[str] = None,
        name: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        given_name: Optional[str] = None,
        middle_name: Optional[str] = None,
        family_name: Optional[str] = None,
        picture: Optional[str] = None,
        custom_attributes: Optional[dict] = None,
        family_scoped_attributes: Optional[dict] = None,
    ) -> dict:
        """
        Create a dependent user in a family. A dependent is a user with no login credentials of their own,
        managed by the family's members.

        Args:
        family_id (str): The ID of the family to create the dependent in.
        login_id (str): Optional login ID. When omitted it is derived from the name. The email and phone
            are never used as the login ID, since a dependent may share them with their guardian.
        name (str): Optional display name.
        email (str): Optional email address.
        phone (str): Optional phone number.
        given_name (str): Optional given name.
        middle_name (str): Optional middle name.
        family_name (str): Optional family name.
        picture (str): Optional URL of the user's picture.
        custom_attributes (dict): Optional, the user's custom attribute values.
        family_scoped_attributes (dict): Optional, family-scoped custom attribute values, in the
            format {<family_id>: {<attribute_name>: <value>}}.

        Return value (dict):
        Return dict in the format
             {"user": {}}
        Containing the created dependent user information.

        Raise:
        AuthException: raised if create operation fails
        """
        response = await self._http.post(
            MgmtV1.family_dependent_create_path,
            body=FamilyBase._compose_create_dependent_body(
                family_id,
                login_id,
                name,
                email,
                phone,
                given_name,
                middle_name,
                family_name,
                picture,
                custom_attributes,
                family_scoped_attributes,
            ),
        )
        return response.json()

    async def delete_dependent(self, user_id: str) -> None:
        """
        Delete a dependent user. The family is inferred from the dependent. Regular (non-dependent)
        family members are removed from a family with `user.remove_families`, not deleted.
        IMPORTANT: This action is irreversible. Use carefully.

        Args:
        user_id (str): The user ID of the dependent to delete.

        Raise:
        AuthException: raised if delete operation fails
        """
        await self._http.post(MgmtV1.family_dependent_delete_path, body={"userId": user_id})

    async def impersonate_dependent(
        self,
        impersonator_user_id_or_login_id: str,
        dependent_login_id: str,
        selected_family: Optional[str] = None,
    ) -> str:
        """
        Impersonate a family dependent. The impersonator must be a member of the dependent's family
        and hold the "Family Impersonate Dependents" permission in that family.

        Args:
        impersonator_user_id_or_login_id (str): The user ID or login ID of the impersonating family member.
        dependent_login_id (str): The login ID of the dependent to impersonate.
        selected_family (str): Optional family to scope the impersonated session to. When set, it must be
            the dependent's family.

        Return value (str): A JWT of the impersonated dependent

        Raise:
        AuthException: raised if impersonation fails
        """
        response = await self._http.post(
            MgmtV1.family_impersonate_path,
            body=FamilyBase._compose_impersonate_body(
                impersonator_user_id_or_login_id, dependent_login_id, selected_family
            ),
        )
        return response.json().get("jwt", "")

    async def stop_impersonation(
        self,
        jwt: str,
        custom_claims: Optional[dict] = None,
        refresh_duration: Optional[int] = None,
    ) -> str:
        """
        Stop impersonating a family dependent and return to the impersonating member's own session.

        Args:
        jwt (str): The impersonation JWT to stop.
        custom_claims (dict): Optional custom claims to add to the JWT.
        refresh_duration (int): Optional duration in seconds for which the new JWT will be valid.

        Return value (str): A JWT of the impersonating family member

        Raise:
        AuthException: raised if the operation fails
        """
        response = await self._http.post(
            MgmtV1.family_stop_impersonation_path,
            body=FamilyBase._compose_stop_impersonation_body(jwt, custom_claims, refresh_duration),
        )
        return response.json().get("jwt", "")

    async def load_settings(self) -> dict:
        """
        Load the project's family account settings.

        Return value (dict):
        Return dict in the format
             {"enabled": <bool>, "maxFamilyMembers": <int>, "allowMultipleFamiliesUsers": <bool>}

        Raise:
        AuthException: raised if load operation fails
        """
        response = await self._http.get(MgmtV1.family_settings_path)
        return response.json()

    async def update_settings(
        self,
        enabled: Optional[bool] = None,
        max_family_members: Optional[int] = None,
        allow_multiple_families_users: Optional[bool] = None,
    ) -> dict:
        """
        Update the project's family account settings. Omitted fields are left unchanged.

        Args:
        enabled (bool): Optional, whether family accounts are enabled for the project.
        max_family_members (int): Optional, the maximum number of members in a single family (at least 1).
        allow_multiple_families_users (bool): Optional, whether a user may belong to more than one family.

        Return value (dict):
        Return dict in the format
             {"enabled": <bool>, "maxFamilyMembers": <int>, "allowMultipleFamiliesUsers": <bool>}
        Containing the updated settings.

        Raise:
        AuthException: raised if update operation fails
        """
        response = await self._http.post(
            MgmtV1.family_settings_path,
            body=FamilyBase._compose_settings_body(enabled, max_family_members, allow_multiple_families_users),
        )
        return response.json()

    async def load_custom_attributes(self) -> dict:
        """
        Load the custom attribute definitions of the family entity itself. These are distinct from the
        family-scoped user attributes managed with `user.load_family_scoped_custom_attributes`.

        Return value (dict):
        Return dict in the format
             {"data": [{"name": <name>, "type": <int>, "displayName": <str>, ...}]}

        Raise:
        AuthException: raised if load operation fails
        """
        response = await self._http.get(MgmtV1.family_load_custom_attributes_path)
        return response.json()

    async def create_custom_attributes(self, attributes: List[CustomAttribute]) -> dict:
        """
        Create custom attribute definitions on the family entity.

        Args:
        attributes (List[CustomAttribute]): The custom attribute definitions to create.

        Return value (dict):
        Return dict in the format
             {"data": [...]}
        Containing the updated custom attribute definitions.

        Raise:
        AuthException: raised if create operation fails
        """
        response = await self._http.post(
            MgmtV1.family_create_custom_attributes_path,
            body={"attributes": custom_attributes_to_dict(attributes)},
        )
        return response.json()

    async def delete_custom_attributes(self, names: List[str]) -> dict:
        """
        Delete custom attribute definitions from the family entity by name.

        Args:
        names (List[str]): The names of the custom attributes to delete.

        Return value (dict):
        Return dict in the format
             {"data": [...]}
        Containing the remaining custom attribute definitions.

        Raise:
        AuthException: raised if delete operation fails
        """
        response = await self._http.post(
            MgmtV1.family_delete_custom_attributes_path,
            body={"names": names},
        )
        return response.json()
