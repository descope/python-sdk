from __future__ import annotations

from typing import List, Optional

from descope._http_base import AsyncHTTPBase
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException  # noqa: F401
from descope.http_client_async import HTTPClientAsync
from descope.management._outbound_application_base import OutboundApplicationBase
from descope.management.common import (
    AccessType,
    MgmtV1,
    PromptType,
    URLParam,
)


class _OutboundApplicationTokenFetcherAsync:
    """Internal async helper class for shared token fetching logic."""

    @staticmethod
    async def fetch_token_by_scopes(
        *,
        http: HTTPClientAsync,
        token: Optional[str] = None,
        app_id: str,
        user_id: str,
        scopes: List[str],
        options: Optional[dict] = None,
        tenant_id: Optional[str] = None,
    ) -> dict:
        """Internal async implementation for fetching token by scopes."""
        uri = MgmtV1.outbound_application_fetch_token_by_scopes_path
        response = await http.post(
            uri,
            body={
                "appId": app_id,
                "userId": user_id,
                "scopes": scopes,
                "options": options,
                "tenantId": tenant_id,
            },
            pswd=token,
        )
        return response.json()

    @staticmethod
    async def fetch_token(
        *,
        http: HTTPClientAsync,
        token: Optional[str] = None,
        app_id: str,
        user_id: str,
        tenant_id: Optional[str] = None,
        options: Optional[dict] = None,
    ) -> dict:
        """Internal async implementation for fetching token."""
        uri = MgmtV1.outbound_application_fetch_token_path
        response = await http.post(
            uri,
            body={
                "appId": app_id,
                "userId": user_id,
                "tenantId": tenant_id,
                "options": options,
            },
            pswd=token,
        )
        return response.json()

    @staticmethod
    async def fetch_tenant_token_by_scopes(
        *,
        http: HTTPClientAsync,
        token: Optional[str] = None,
        app_id: str,
        tenant_id: str,
        scopes: List[str],
        options: Optional[dict] = None,
    ) -> dict:
        """Internal async implementation for fetching tenant token by scopes."""
        uri = MgmtV1.outbound_application_fetch_tenant_token_by_scopes_path
        response = await http.post(
            uri,
            body={
                "appId": app_id,
                "tenantId": tenant_id,
                "scopes": scopes,
                "options": options,
            },
            pswd=token,
        )
        return response.json()

    @staticmethod
    async def fetch_tenant_token(
        *,
        http: HTTPClientAsync,
        token: Optional[str] = None,
        app_id: str,
        tenant_id: str,
        options: Optional[dict] = None,
    ) -> dict:
        """Internal async implementation for fetching tenant token."""
        uri = MgmtV1.outbound_application_fetch_tenant_token_path
        response = await http.post(
            uri,
            body={
                "appId": app_id,
                "tenantId": tenant_id,
                "options": options,
            },
            pswd=token,
        )
        return response.json()


class OutboundApplicationAsync(OutboundApplicationBase, AsyncHTTPBase):
    async def create_application(
        self,
        name: str,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        id: Optional[str] = None,
        client_secret: Optional[str] = None,
        client_id: Optional[str] = None,
        discovery_url: Optional[str] = None,
        authorization_url: Optional[str] = None,
        authorization_url_params: Optional[List[URLParam]] = None,
        token_url: Optional[str] = None,
        token_url_params: Optional[List[URLParam]] = None,
        revocation_url: Optional[str] = None,
        default_scopes: Optional[List[str]] = None,
        default_redirect_url: Optional[str] = None,
        callback_domain: Optional[str] = None,
        pkce: Optional[bool] = None,
        access_type: Optional[AccessType] = None,
        prompt: Optional[List[PromptType]] = None,
    ) -> dict:
        """
        Create a new outbound application with the given name. Outbound application IDs are provisioned automatically, but can be provided
        explicitly if needed. Both the name and ID must be unique per project.

        Args:
        name (str): The outbound application's name.
        description (str): Optional outbound application description.
        logo (str): Optional outbound application logo.
        id (str): Optional outbound application ID.
        client_secret (str): Optional client secret for the application.
        client_id (str): Optional client ID for the application.
        discovery_url (str): Optional OAuth discovery URL.
        authorization_url (str): Optional OAuth authorization URL.
        authorization_url_params (List[URLParam]): Optional authorization URL parameters.
        token_url (str): Optional OAuth token URL.
        token_url_params (List[URLParam]): Optional token URL parameters.
        revocation_url (str): Optional OAuth token revocation URL.
        default_scopes (List[str]): Optional default OAuth scopes.
        default_redirect_url (str): Optional default redirect URL.
        callback_domain (str): Optional callback domain.
        pkce (bool): Optional PKCE (Proof Key for Code Exchange) support.
        access_type (AccessType): Optional OAuth access type.
        prompt (List[PromptType]): Optional OAuth prompt parameters.

        Return value (dict):
        Return dict in the format
             {"app": {"id": <id>, "name": <name>, "description": <description>, "logo": <logo>}}

        Raise:
        AuthException: raised if create operation fails
        """
        uri = MgmtV1.outbound_application_create_path
        response = await self._http.post(
            uri,
            body=OutboundApplicationBase._compose_create_update_body(
                name,
                description,
                logo,
                id,
                client_secret,
                client_id,
                discovery_url,
                authorization_url,
                authorization_url_params,
                token_url,
                token_url_params,
                revocation_url,
                default_scopes,
                default_redirect_url,
                callback_domain,
                pkce,
                access_type,
                prompt,
            ),
        )
        return response.json()

    async def update_application(
        self,
        id: str,
        name: str,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        client_secret: Optional[str] = None,
        client_id: Optional[str] = None,
        discovery_url: Optional[str] = None,
        authorization_url: Optional[str] = None,
        authorization_url_params: Optional[List[URLParam]] = None,
        token_url: Optional[str] = None,
        token_url_params: Optional[List[URLParam]] = None,
        revocation_url: Optional[str] = None,
        default_scopes: Optional[List[str]] = None,
        default_redirect_url: Optional[str] = None,
        callback_domain: Optional[str] = None,
        pkce: Optional[bool] = None,
        access_type: Optional[AccessType] = None,
        prompt: Optional[List[PromptType]] = None,
    ) -> dict:
        """
        Update an existing outbound application with the given parameters. IMPORTANT: All parameters are used as overrides
        to the existing outbound application. Empty fields will override populated fields. Use carefully.

        Args:
        id (str): The ID of the outbound application to update.
        name (str): Updated outbound application name.
        description (str): Optional outbound application description.
        logo (str): Optional outbound application logo.
        client_secret (str): Optional client secret for the application.
        client_id (str): Optional client ID for the application.
        discovery_url (str): Optional OAuth discovery URL.
        authorization_url (str): Optional OAuth authorization URL.
        authorization_url_params (List[URLParam]): Optional authorization URL parameters.
        token_url (str): Optional OAuth token URL.
        token_url_params (List[URLParam]): Optional token URL parameters.
        revocation_url (str): Optional OAuth token revocation URL.
        default_scopes (List[str]): Optional default OAuth scopes.
        default_redirect_url (str): Optional default redirect URL.
        callback_domain (str): Optional callback domain.
        pkce (bool): Optional PKCE (Proof Key for Code Exchange) support.
        access_type (AccessType): Optional OAuth access type.
        prompt (List[PromptType]): Optional OAuth prompt parameters.

        Return value (dict):
        Return dict in the format
             {"app": {"id": <id>, "name": <name>, "description": <description>, "logo": <logo>}}

        Raise:
        AuthException: raised if update operation fails
        """
        uri = MgmtV1.outbound_application_update_path
        response = await self._http.post(
            uri,
            body={
                "app": OutboundApplicationBase._compose_create_update_body(
                    name,
                    description,
                    logo,
                    id,
                    client_secret,
                    client_id,
                    discovery_url,
                    authorization_url,
                    authorization_url_params,
                    token_url,
                    token_url_params,
                    revocation_url,
                    default_scopes,
                    default_redirect_url,
                    callback_domain,
                    pkce,
                    access_type,
                    prompt,
                )
            },
        )
        return response.json()

    async def delete_application(
        self,
        id: str,
    ):
        """
        Delete an existing outbound application. IMPORTANT: This action is irreversible. Use carefully.

        Args:
        id (str): The ID of the outbound application that's to be deleted.

        Raise:
        AuthException: raised if deletion operation fails
        """
        uri = MgmtV1.outbound_application_delete_path
        await self._http.post(uri, body={"id": id})

    async def load_application(
        self,
        id: str,
    ) -> dict:
        """
        Load outbound application by id.

        Args:
        id (str): The ID of the outbound application to load.

        Return value (dict):
        Return dict in the format
             {"app": {"id": <id>, "name": <name>, "description": <description>, "logo": <logo>}}
        Containing the loaded outbound application information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = await self._http.get(f"{MgmtV1.outbound_application_load_path}/{id}")
        return response.json()

    async def load_all_applications(self) -> dict:
        """
        Load all outbound applications.

        Return value (dict):
        Return dict in the format
             {"apps": [{"id": <id>, "name": <name>, "description": <description>, "logo": <logo>}, ...]}
        Containing the loaded outbound applications information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = await self._http.get(MgmtV1.outbound_application_load_all_path)
        return response.json()

    async def fetch_token_by_scopes(
        self,
        app_id: str,
        user_id: str,
        scopes: List[str],
        options: Optional[dict] = None,
        tenant_id: Optional[str] = None,
    ) -> dict:
        """
        Fetch an outbound application token for a user with specific scopes.

        Args:
        app_id (str): The ID of the outbound application.
        user_id (str): The ID of the user.
        scopes (List[str]): List of scopes to include in the token.
        options (dict): Optional token options.
        tenant_id (str): Optional tenant ID.

        Return value (dict):
        Return dict in the format
             {"token": {"token": <access_token>, "refreshToken": <refresh_token>, "expiresIn": <expires_in>, "tokenType": <token_type>, "scopes": <scopes>}}

        Raise:
        AuthException: raised if fetch operation fails
        """
        return await _OutboundApplicationTokenFetcherAsync.fetch_token_by_scopes(
            http=self._http,
            app_id=app_id,
            user_id=user_id,
            scopes=scopes,
            options=options,
            tenant_id=tenant_id,
        )

    async def fetch_token(
        self,
        app_id: str,
        user_id: str,
        tenant_id: Optional[str] = None,
        options: Optional[dict] = None,
    ) -> dict:
        """
        Fetch an outbound application token for a user.

        Args:
        app_id (str): The ID of the outbound application.
        user_id (str): The ID of the user.
        tenant_id (str): Optional tenant ID.
        options (dict): Optional token options.

        Return value (dict):
        Return dict in the format
             {"token": {"token": <access_token>, "refreshToken": <refresh_token>, "expiresIn": <expires_in>, "tokenType": <token_type>, "scopes": <scopes>}}

        Raise:
        AuthException: raised if fetch operation fails
        """
        return await _OutboundApplicationTokenFetcherAsync.fetch_token(
            http=self._http,
            app_id=app_id,
            user_id=user_id,
            tenant_id=tenant_id,
            options=options,
        )

    async def fetch_tenant_token_by_scopes(
        self,
        app_id: str,
        tenant_id: str,
        scopes: List[str],
        options: Optional[dict] = None,
    ) -> dict:
        """
        Fetch an outbound application token for a tenant with specific scopes.

        Args:
        app_id (str): The ID of the outbound application.
        tenant_id (str): The ID of the tenant.
        scopes (List[str]): List of scopes to include in the token.
        options (dict): Optional token options.

        Return value (dict):
        Return dict in the format
             {"token": {"token": <access_token>, "refreshToken": <refresh_token>, "expiresIn": <expires_in>, "tokenType": <token_type>, "scopes": <scopes>}}

        Raise:
        AuthException: raised if fetch operation fails
        """
        return await _OutboundApplicationTokenFetcherAsync.fetch_tenant_token_by_scopes(
            http=self._http,
            app_id=app_id,
            tenant_id=tenant_id,
            scopes=scopes,
            options=options,
        )

    async def fetch_tenant_token(
        self,
        app_id: str,
        tenant_id: str,
        options: Optional[dict] = None,
    ) -> dict:
        """
        Fetch an outbound application token for a tenant.

        Args:
        app_id (str): The ID of the outbound application.
        tenant_id (str): The ID of the tenant.
        options (dict): Optional token options.

        Return value (dict):
        Return dict in the format
             {"token": {"token": <access_token>, "refreshToken": <refresh_token>, "expiresIn": <expires_in>, "tokenType": <token_type>, "scopes": <scopes>}}

        Raise:
        AuthException: raised if fetch operation fails
        """
        return await _OutboundApplicationTokenFetcherAsync.fetch_tenant_token(
            http=self._http,
            app_id=app_id,
            tenant_id=tenant_id,
            options=options,
        )

    async def delete_user_tokens(
        self,
        app_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        """
        Delete outbound application tokens by app ID and/or user ID.
        At least one of app_id or user_id must be provided.

        Args:
        app_id (str): Optional ID of the outbound application.
        user_id (str): Optional ID of the user.

        Raise:
        AuthException: raised if delete operation fails
        """
        params = {}
        if app_id:
            params["appId"] = app_id
        if user_id:
            params["userId"] = user_id
        uri = MgmtV1.outbound_application_delete_user_tokens_path
        await self._http.delete(uri, params=params)

    async def delete_token(
        self,
        token_id: str,
    ):
        """
        Delete an outbound application token by its ID.

        Args:
        token_id (str): The ID of the token to delete.

        Raise:
        AuthException: raised if delete operation fails
        """
        uri = MgmtV1.outbound_application_delete_token_path
        await self._http.delete(uri, params={"id": token_id})

    async def list_apps_with_user_token(
        self,
        user_id: str,
        tenant_id: Optional[str] = None,
    ) -> dict:
        """
        List the IDs of the outbound applications the given user currently holds a valid token for.
        Use this for connection-status views instead of calling fetch_token once per application.

        Args:
        user_id (str): The ID of the user.
        tenant_id (str): Optional tenant ID to scope the lookup to.

        Return value (dict):
        Return dict in the format
             {"appIds": [<app_id>, ...]}

        Raise:
        AuthException: raised if the operation fails
        """
        params = {"userId": user_id}
        if tenant_id:
            params["tenantId"] = tenant_id
        response = await self._http.get(
            MgmtV1.outbound_application_list_apps_with_user_token_path,
            params=params,
        )
        return response.json()

    async def upload_user_api_key(
        self,
        app_id: str,
        user_id: str,
        api_key: str,
        tenant_id: Optional[str] = None,
    ) -> dict:
        """
        Upload (set) a static API key for a user on an apikey-type outbound application.

        Args:
        app_id (str): The ID of the outbound application.
        user_id (str): The ID of the user.
        api_key (str): The API key to store for the user.
        tenant_id (str): Optional tenant ID, used to associate different keys for the
            same user in different tenants.

        Raise:
        AuthException: raised if the operation fails
        """
        body: dict = {"appId": app_id, "userId": user_id, "apiKey": api_key}
        if tenant_id is not None:
            body["tenantId"] = tenant_id
        response = await self._http.post(
            MgmtV1.outbound_application_upload_user_api_key_path,
            body=body,
        )
        return response.json()

    async def upload_tenant_api_key(
        self,
        app_id: str,
        tenant_id: str,
        api_key: str,
    ) -> dict:
        """
        Upload (set) a static API key for a tenant on an apikey-type outbound application.

        Args:
        app_id (str): The ID of the outbound application.
        tenant_id (str): The ID of the tenant.
        api_key (str): The API key to store for the tenant.

        Raise:
        AuthException: raised if the operation fails
        """
        response = await self._http.post(
            MgmtV1.outbound_application_upload_tenant_api_key_path,
            body={"appId": app_id, "tenantId": tenant_id, "apiKey": api_key},
        )
        return response.json()

    async def upload_user_token(
        self,
        app_id: str,
        user_id: str,
        tenant_id: Optional[str] = None,
        refresh_token: Optional[str] = None,
        access_token: Optional[str] = None,
        access_token_expiry: Optional[int] = None,
        access_token_type: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        external_identifier: Optional[str] = None,
        id_token: Optional[str] = None,
        verify_refresh: Optional[bool] = None,
        granted_by: Optional[str] = None,
    ) -> dict:
        """
        Upload (migrate) an existing OAuth token for a user on an oauth-type outbound application,
        without requiring the user to re-run the OAuth flow. At least one of refresh_token or
        access_token must be provided.

        Args:
        app_id (str): The ID of the outbound application.
        user_id (str): The ID of the user.
        tenant_id (str): Optional tenant ID.
        refresh_token (str): Optional refresh token.
        access_token (str): Optional access token.
        access_token_expiry (int): Optional access token expiry, in epoch seconds.
        access_token_type (str): Optional token type (defaults to "Bearer").
        scopes (List[str]): Optional scopes the token was granted for.
        external_identifier (str): Optional external identifier.
        id_token (str): Optional id token.
        verify_refresh (bool): If True, verify the refresh token against the provider before
            persisting; nothing is written if verification fails.
        granted_by (str): Optional attribution for who granted the token.

        Raise:
        AuthException: raised if the operation fails
        """
        base: dict = {"appId": app_id, "userId": user_id}
        if tenant_id is not None:
            base["tenantId"] = tenant_id
        body = OutboundApplicationBase._compose_oauth_upload_body(
            base,
            refresh_token,
            access_token,
            access_token_expiry,
            access_token_type,
            scopes,
            external_identifier,
            id_token,
            granted_by,
            verify_refresh,
        )
        response = await self._http.post(
            MgmtV1.outbound_application_upload_user_token_path,
            body=body,
        )
        return response.json()

    async def upload_tenant_token(
        self,
        app_id: str,
        tenant_id: str,
        refresh_token: Optional[str] = None,
        access_token: Optional[str] = None,
        access_token_expiry: Optional[int] = None,
        access_token_type: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        external_identifier: Optional[str] = None,
        id_token: Optional[str] = None,
        verify_refresh: Optional[bool] = None,
        granted_by: Optional[str] = None,
    ) -> dict:
        """
        Upload (migrate) an existing OAuth token for a tenant on an oauth-type outbound application.
        At least one of refresh_token or access_token must be provided.

        Args:
        app_id (str): The ID of the outbound application.
        tenant_id (str): The ID of the tenant.
        (remaining args): see upload_user_token.

        Raise:
        AuthException: raised if the operation fails
        """
        base: dict = {"appId": app_id, "tenantId": tenant_id}
        body = OutboundApplicationBase._compose_oauth_upload_body(
            base,
            refresh_token,
            access_token,
            access_token_expiry,
            access_token_type,
            scopes,
            external_identifier,
            id_token,
            granted_by,
            verify_refresh,
        )
        response = await self._http.post(
            MgmtV1.outbound_application_upload_tenant_token_path,
            body=body,
        )
        return response.json()

    async def batch_upload_user_tokens(self, tokens: List[dict]) -> dict:
        """
        Batch upload (migrate) existing OAuth tokens for users. All-or-nothing: if any item fails
        per-item validation, the returned failures are populated and no tokens are committed.

        Args:
        tokens (List[dict]): A list of token dicts, each with at least appId and userId plus one of
            refreshToken / accessToken. See upload_user_token for the full set of fields
            (verifyRefresh is not supported for batch uploads).

        Return value (dict):
        Return dict in the format
             {"failures": [{"appId": <id>, "userId": <id>, "errorCode": <code>, "reason": <reason>}, ...]}

        Raise:
        AuthException: raised if the operation fails
        """
        response = await self._http.post(
            MgmtV1.outbound_application_batch_upload_user_tokens_path,
            body={"tokens": tokens},
        )
        return response.json()

    async def batch_upload_tenant_tokens(self, tokens: List[dict]) -> dict:
        """
        Batch upload (migrate) existing OAuth tokens for tenants. All-or-nothing: if any item fails
        per-item validation, the returned failures are populated and no tokens are committed.

        Args:
        tokens (List[dict]): A list of token dicts, each with at least appId and tenantId plus one of
            refreshToken / accessToken.

        Return value (dict):
        Return dict in the format
             {"failures": [{"appId": <id>, "tenantId": <id>, "errorCode": <code>, "reason": <reason>}, ...]}

        Raise:
        AuthException: raised if the operation fails
        """
        response = await self._http.post(
            MgmtV1.outbound_application_batch_upload_tenant_tokens_path,
            body={"tokens": tokens},
        )
        return response.json()


class OutboundApplicationByTokenAsync(AsyncHTTPBase):
    def __init__(self, http_client: HTTPClientAsync):
        # This class expects the token to be passed for each call
        no_key_client = HTTPClientAsync(
            project_id=http_client.project_id,
            base_url=http_client.base_url,
            timeout_seconds=http_client.timeout_seconds,
            secure=http_client.secure,
            management_key=None,  # Override the management key for this client
        )
        super().__init__(no_key_client)

    async def aclose(self) -> None:
        """Close the dedicated no-management-key HTTP client this instance owns."""
        await self._http.aclose()

    # Methods for fetching outbound application tokens using an inbound application token
    # that includes the "outbound.token.fetch" scope (no management key required)

    def _check_inbound_app_token(self, token: str):
        """Check if inbound app token is available for the given property."""
        if not token:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                "Inbound app token is required for perform this functionality",
            )

    async def fetch_token_by_scopes(
        self,
        token: str,
        app_id: str,
        user_id: str,
        scopes: List[str],
        options: Optional[dict] = None,
        tenant_id: Optional[str] = None,
    ) -> dict:
        """
        Fetch an outbound application token for a user with specific scopes.

        Args:
        token (str): The Inbound Application token to use for authentication.
        app_id (str): The ID of the outbound application.
        user_id (str): The ID of the user.
        scopes (List[str]): List of scopes to include in the token.
        options (dict): Optional token options.
        tenant_id (str): Optional tenant ID.

        Return value (dict):
        Return dict in the format
             {"token": {"token": <access_token>, "refreshToken": <refresh_token>, "expiresIn": <expires_in>, "tokenType": <token_type>, "scopes": <scopes>}}

        Raise:
        AuthException: raised if fetch operation fails
        """
        self._check_inbound_app_token(token)
        return await _OutboundApplicationTokenFetcherAsync.fetch_token_by_scopes(
            http=self._http,
            token=token,
            app_id=app_id,
            user_id=user_id,
            scopes=scopes,
            options=options,
            tenant_id=tenant_id,
        )

    async def fetch_token(
        self,
        token: str,
        app_id: str,
        user_id: str,
        tenant_id: Optional[str] = None,
        options: Optional[dict] = None,
    ) -> dict:
        """
        Fetch an outbound application token for a user.

        Args:
        token (str): The Inbound Application token to use for authentication.
        app_id (str): The ID of the outbound application.
        user_id (str): The ID of the user.
        tenant_id (str): Optional tenant ID.
        options (dict): Optional token options.

        Return value (dict):
        Return dict in the format
             {"token": {"token": <access_token>, "refreshToken": <refresh_token>, "expiresIn": <expires_in>, "tokenType": <token_type>, "scopes": <scopes>}}

        Raise:
        AuthException: raised if fetch operation fails
        """
        self._check_inbound_app_token(token)
        return await _OutboundApplicationTokenFetcherAsync.fetch_token(
            http=self._http,
            token=token,
            app_id=app_id,
            user_id=user_id,
            tenant_id=tenant_id,
            options=options,
        )

    async def fetch_tenant_token_by_scopes(
        self,
        token: str,
        app_id: str,
        tenant_id: str,
        scopes: List[str],
        options: Optional[dict] = None,
    ) -> dict:
        """
        Fetch an outbound application token for a tenant with specific scopes.

        Args:
        token (str): The Inbound Application token to use for authentication.
        app_id (str): The ID of the outbound application.
        tenant_id (str): The ID of the tenant.
        scopes (List[str]): List of scopes to include in the token.
        options (dict): Optional token options.

        Return value (dict):
        Return dict in the format
             {"token": {"token": <access_token>, "refreshToken": <refresh_token>, "expiresIn": <expires_in>, "tokenType": <token_type>, "scopes": <scopes>}}

        Raise:
        AuthException: raised if fetch operation fails
        """
        self._check_inbound_app_token(token)
        return await _OutboundApplicationTokenFetcherAsync.fetch_tenant_token_by_scopes(
            http=self._http,
            token=token,
            app_id=app_id,
            tenant_id=tenant_id,
            scopes=scopes,
            options=options,
        )

    async def fetch_tenant_token(
        self,
        token: str,
        app_id: str,
        tenant_id: str,
        options: Optional[dict] = None,
    ) -> dict:
        """
        Fetch an outbound application token for a tenant.

        Args:
        token (str): The Inbound Application token to use for authentication.
        app_id (str): The ID of the outbound application.
        tenant_id (str): The ID of the tenant.
        options (dict): Optional token options.

        Return value (dict):
        Return dict in the format
             {"token": {"token": <access_token>, "refreshToken": <refresh_token>, "expiresIn": <expires_in>, "tokenType": <token_type>, "scopes": <scopes>}}

        Raise:
        AuthException: raised if fetch operation fails
        """
        self._check_inbound_app_token(token)
        return await _OutboundApplicationTokenFetcherAsync.fetch_tenant_token(
            http=self._http,
            token=token,
            app_id=app_id,
            tenant_id=tenant_id,
            options=options,
        )
