from __future__ import annotations

from typing import Any, Dict, List, Optional

from descope._http_base import AsyncHTTPBase
from descope.management._third_party_application_base import compose_create_update_body
from descope.management.common import MgmtV1


class ThirdPartyApplicationAsync(AsyncHTTPBase):
    async def create(
        self,
        name: str,
        login_page_url: str,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        approved_callback_urls: Optional[List[str]] = None,
        permissions_scopes: Optional[List[Dict[str, Any]]] = None,
        attributes_scopes: Optional[List[Dict[str, Any]]] = None,
        jwt_bearer_settings: Optional[Dict[str, Any]] = None,
        custom_attributes: Optional[Dict[str, Any]] = None,
        force_pkce: Optional[bool] = None,
        default_audience: Optional[str] = None,
    ) -> dict:
        """
        Create a new third party application with the given parameters.

        Args:
        name (str): The third party application's name (must be unique per project).
        login_page_url (str): The URL where login page is hosted.
        description (str): Optional third party application description.
        logo (str): Optional third party application logo.
        approved_callback_urls (List[str]): Optional list of approved callback URLs.
        permissions_scopes (List[Dict[str, Any]]): Optional list of permissions scopes.
            Each scope is a dict with keys: name, description, values.
        attributes_scopes (List[Dict[str, Any]]): Optional list of attributes scopes.
            Each scope is a dict with keys: name, description, values.
        jwt_bearer_settings (Dict[str, Any]): Optional JWT Bearer settings which used to validate external token.
            Dict with key 'issuers' mapping to issuer settings.
        custom_attributes (Dict[str, Any]): Optional custom attributes.
        force_pkce (bool): Optional flag to require PKCE on the authorization-code flow.
        default_audience (str): Optional default aud of issued tokens: "projectId", "clientId", or "" (both).

        Return value (dict):
        Return dict in the format
             {"id": "<id>", "cleartext": "<secret>"}
        Containing the created third party application ID and secret.

        Raise:
        AuthException: raised if creation operation fails
        """
        body = compose_create_update_body(
            name=name,
            login_page_url=login_page_url,
            description=description,
            logo=logo,
            approved_callback_urls=approved_callback_urls,
            permissions_scopes=permissions_scopes,
            attributes_scopes=attributes_scopes,
            jwt_bearer_settings=jwt_bearer_settings,
            custom_attributes=custom_attributes,
            force_pkce=force_pkce,
            default_audience=default_audience,
        )
        response = await self._http.post(MgmtV1.thirdparty_application_create_path, body=body)
        return response.json()

    async def update(
        self,
        id: str,
        name: str,
        login_page_url: str,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        approved_callback_urls: Optional[List[str]] = None,
        permissions_scopes: Optional[List[Dict[str, Any]]] = None,
        attributes_scopes: Optional[List[Dict[str, Any]]] = None,
        jwt_bearer_settings: Optional[Dict[str, Any]] = None,
        custom_attributes: Optional[Dict[str, Any]] = None,
        force_pkce: Optional[bool] = None,
        default_audience: Optional[str] = None,
    ):
        """
        Update an existing third party application with the given parameters.
        IMPORTANT: All parameters are required and will override whatever value is currently
        set in the existing third party application. Use carefully.

        Args:
        id (str): The ID of the third party application to update.
        name (str): Updated third party application name.
        login_page_url (str): The URL where login page is hosted.
        description (str): Optional third party application description.
        logo (str): Optional third party application logo.
        approved_callback_urls (List[str]): Optional list of approved callback URLs.
        permissions_scopes (List[Dict[str, Any]]): Optional list of permissions scopes.
        attributes_scopes (List[Dict[str, Any]]): Optional list of attributes scopes.
        jwt_bearer_settings (Dict[str, Any]): Optional JWT Bearer settings.
        custom_attributes (Dict[str, Any]): Optional custom attributes.
        force_pkce (bool): Optional flag to require PKCE on the authorization-code flow.
        default_audience (str): Optional default aud of issued tokens.

        Raise:
        AuthException: raised if update operation fails
        """
        body = compose_create_update_body(
            name=name,
            login_page_url=login_page_url,
            id=id,
            description=description,
            logo=logo,
            approved_callback_urls=approved_callback_urls,
            permissions_scopes=permissions_scopes,
            attributes_scopes=attributes_scopes,
            jwt_bearer_settings=jwt_bearer_settings,
            custom_attributes=custom_attributes,
            force_pkce=force_pkce,
            default_audience=default_audience,
        )
        await self._http.post(MgmtV1.thirdparty_application_update_path, body=body)

    async def patch(
        self,
        id: str,
        name: Optional[str] = None,
        login_page_url: Optional[str] = None,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        approved_callback_urls: Optional[List[str]] = None,
        permissions_scopes: Optional[List[Dict[str, Any]]] = None,
        attributes_scopes: Optional[List[Dict[str, Any]]] = None,
        jwt_bearer_settings: Optional[Dict[str, Any]] = None,
        custom_attributes: Optional[Dict[str, Any]] = None,
        force_pkce: Optional[bool] = None,
        default_audience: Optional[str] = None,
    ):
        """
        Patch an existing third party application with the given parameters.
        Only provided fields will be updated.

        Args:
        id (str): The ID of the third party application to patch (required).
        name (str): Optional updated third party application name.
        login_page_url (str): Optional URL where login page is hosted.
        description (str): Optional third party application description.
        logo (str): Optional third party application logo.
        approved_callback_urls (List[str]): Optional list of approved callback URLs.
        permissions_scopes (List[Dict[str, Any]]): Optional list of permissions scopes.
        attributes_scopes (List[Dict[str, Any]]): Optional list of attributes scopes.
        jwt_bearer_settings (Dict[str, Any]): Optional JWT Bearer settings.
        custom_attributes (Dict[str, Any]): Optional custom attributes.
        force_pkce (bool): Optional flag to require PKCE on the authorization-code flow.
        default_audience (str): Optional default aud of issued tokens.

        Raise:
        AuthException: raised if patch operation fails
        """
        body: Dict[str, Any] = {"id": id}
        if name is not None:
            body["name"] = name
        if login_page_url is not None:
            body["loginPageUrl"] = login_page_url
        if description is not None:
            body["description"] = description
        if logo is not None:
            body["logo"] = logo
        if approved_callback_urls is not None:
            body["approvedCallbackUrls"] = approved_callback_urls
        if permissions_scopes is not None:
            body["permissionsScopes"] = permissions_scopes
        if attributes_scopes is not None:
            body["attributesScopes"] = attributes_scopes
        if jwt_bearer_settings is not None:
            body["jwtBearerSettings"] = jwt_bearer_settings
        if custom_attributes is not None:
            body["customAttributes"] = custom_attributes
        if force_pkce is not None:
            body["forcePkce"] = force_pkce
        if default_audience is not None:
            body["defaultAudience"] = default_audience
        await self._http.post(MgmtV1.thirdparty_application_patch_path, body=body)

    async def delete(self, id: str):
        """
        Delete an existing third party application.
        IMPORTANT: This action is irreversible. Use carefully.

        Args:
        id (str): The ID of the third party application to delete.

        Raise:
        AuthException: raised if deletion operation fails
        """
        await self._http.post(MgmtV1.thirdparty_application_delete_path, body={"id": id})

    async def delete_batch(self, ids: List[str]):
        """
        Delete multiple third party applications by id in a single request.
        IMPORTANT: This action is irreversible. Use carefully.

        Args:
        ids (List[str]): List of third party application IDs to delete.

        Raise:
        AuthException: raised if deletion operation fails
        """
        await self._http.post(MgmtV1.thirdparty_application_delete_batch_path, body={"ids": ids})

    async def load(self, id: str) -> dict:
        """
        Load third party application by id.

        Args:
        id (str): The ID of the third party application to load.

        Return value (dict):
        Return dict containing the loaded third party application information with keys:
        id, name, description, logo, loginPageUrl, clientId, approvedCallbackUrls,
        permissionsScopes, attributesScopes, jwtBearerSettings, customAttributes,
        forcePkce, defaultAudience.

        Raise:
        AuthException: raised if load operation fails
        """
        response = await self._http.get(MgmtV1.thirdparty_application_load_path, params={"id": id})
        return response.json()

    async def load_all(self) -> dict:
        """
        Load all third party applications.

        Return value (dict):
        Return dict in the format
             {"apps": [<array of third party application objects>]}
        Containing all third party applications.

        Raise:
        AuthException: raised if load operation fails
        """
        response = await self._http.get(MgmtV1.thirdparty_application_load_all_path)
        return response.json()

    async def rotate_secret(self, id: str) -> dict:
        """
        Rotate the application secret for a third party application by the application id.

        Args:
        id (str): The ID of the third party application.

        Return value (dict):
        Return dict in the format
             {"cleartext": "<new_secret>"}
        Containing the new application secret.

        Raise:
        AuthException: raised if rotation operation fails
        """
        response = await self._http.post(MgmtV1.thirdparty_application_rotate_path, body={"id": id})
        return response.json()

    async def get_secret(self, id: str) -> dict:
        """
        Get the application secret for a third party application by the application id.

        Args:
        id (str): The ID of the third party application.

        Return value (dict):
        Return dict in the format
             {"cleartext": "<secret>"}
        Containing the application secret.

        Raise:
        AuthException: raised if get operation fails
        """
        response = await self._http.get(MgmtV1.thirdparty_application_secret_path, params={"id": id})
        return response.json()

    async def delete_consents(
        self,
        consent_ids: Optional[List[str]] = None,
        app_id: Optional[str] = None,
        user_ids: Optional[List[str]] = None,
        tenant_id: Optional[str] = None,
    ):
        """
        Delete consents for third party applications.

        Args:
        consent_ids (List[str]): Optional list of consent IDs to delete.
        app_id (str): Optional application ID to filter by.
        user_ids (List[str]): Optional list of user IDs to filter by.
        tenant_id (str): Optional tenant ID to filter by.

        Raise:
        AuthException: raised if deletion operation fails
        """
        body: Dict[str, Any] = {}
        if consent_ids is not None:
            body["consentIds"] = consent_ids
        if app_id is not None:
            body["appId"] = app_id
        if user_ids is not None:
            body["userIds"] = user_ids
        if tenant_id is not None:
            body["tenantId"] = tenant_id
        await self._http.post(MgmtV1.thirdparty_consents_delete_path, body=body)

    async def delete_tenant_consents(self, tenant_id: str):
        """
        Delete all consents for a specific tenant.

        Args:
        tenant_id (str): The tenant ID.

        Raise:
        AuthException: raised if deletion operation fails
        """
        await self._http.post(MgmtV1.thirdparty_consents_delete_tenant_path, body={"tenantId": tenant_id})

    async def search_consents(
        self,
        app_id: Optional[str] = None,
        user_id: Optional[str] = None,
        consent_id: Optional[str] = None,
        page: Optional[int] = None,
        limit: Optional[int] = None,
        tenant_id: Optional[str] = None,
    ) -> dict:
        """
        Search consents for third party applications.

        Args:
        app_id (str): Optional application ID to filter by.
        user_id (str): Optional user ID to filter by.
        consent_id (str): Optional consent ID to filter by.
        page (int): Optional page number for pagination.
        limit (int): Optional limit for pagination.
        tenant_id (str): Optional tenant ID to filter by.

        Return value (dict):
        Return dict containing the search results with consent information.

        Raise:
        AuthException: raised if search operation fails
        """
        body: Dict[str, Any] = {}
        if app_id is not None:
            body["appId"] = app_id
        if user_id is not None:
            body["userId"] = user_id
        if consent_id is not None:
            body["consentId"] = consent_id
        if page is not None:
            body["page"] = page
        if limit is not None:
            body["limit"] = limit
        if tenant_id is not None:
            body["tenantId"] = tenant_id
        response = await self._http.post(MgmtV1.thirdparty_consents_search_path, body=body)
        return response.json()
