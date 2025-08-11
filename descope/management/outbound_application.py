from typing import Any, List, Optional

from descope._auth_base import AuthBase
from descope.auth import Auth
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException  # noqa: F401
from descope.management.common import (
    AccessType,
    MgmtV1,
    PromptType,
    URLParam,
    url_params_to_dict,
)


class _OutboundApplicationTokenFetcher:
    """Internal helper class for shared token fetching logic."""

    @staticmethod
    def fetch_token_by_scopes(
        auth_instance: Auth,
        token: str,
        app_id: str,
        user_id: str,
        scopes: List[str],
        options: Optional[dict] = None,
        tenant_id: Optional[str] = None,
    ) -> dict:
        """Internal implementation for fetching token by scopes."""
        uri = MgmtV1.outbound_application_fetch_token_by_scopes_path
        response = auth_instance.do_post(
            uri,
            {
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
    def fetch_token(
        auth_instance: Auth,
        token: str,
        app_id: str,
        user_id: str,
        tenant_id: Optional[str] = None,
        options: Optional[dict] = None,
    ) -> dict:
        """Internal implementation for fetching token."""
        uri = MgmtV1.outbound_application_fetch_token_path
        response = auth_instance.do_post(
            uri,
            {
                "appId": app_id,
                "userId": user_id,
                "tenantId": tenant_id,
                "options": options,
            },
            pswd=token,
        )
        return response.json()

    @staticmethod
    def fetch_tenant_token_by_scopes(
        auth_instance: Auth,
        token: str,
        app_id: str,
        tenant_id: str,
        scopes: List[str],
        options: Optional[dict] = None,
    ) -> dict:
        """Internal implementation for fetching tenant token by scopes."""
        uri = MgmtV1.outbound_application_fetch_tenant_token_by_scopes_path
        response = auth_instance.do_post(
            uri,
            {
                "appId": app_id,
                "tenantId": tenant_id,
                "scopes": scopes,
                "options": options,
            },
            pswd=token,
        )
        return response.json()

    @staticmethod
    def fetch_tenant_token(
        auth_instance: Auth,
        token: str,
        app_id: str,
        tenant_id: str,
        options: Optional[dict] = None,
    ) -> dict:
        """Internal implementation for fetching tenant token."""
        uri = MgmtV1.outbound_application_fetch_tenant_token_path
        response = auth_instance.do_post(
            uri,
            {
                "appId": app_id,
                "tenantId": tenant_id,
                "options": options,
            },
            pswd=token,
        )
        return response.json()


class OutboundApplication(AuthBase):
    def create_application(
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
        response = self._auth.do_post(
            uri,
            OutboundApplication._compose_create_update_body(
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
            pswd=self._auth.management_key,
        )
        return response.json()

    def update_application(
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
        response = self._auth.do_post(
            uri,
            {
                "app": OutboundApplication._compose_create_update_body(
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
            pswd=self._auth.management_key,
        )
        return response.json()

    def delete_application(
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
        self._auth.do_post(uri, {"id": id}, pswd=self._auth.management_key)

    def load_application(
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
        response = self._auth.do_get(
            uri=f"{MgmtV1.outbound_application_load_path}/{id}",
            pswd=self._auth.management_key,
        )
        return response.json()

    def load_all_applications(
        self,
    ) -> dict:
        """
        Load all outbound applications.

        Return value (dict):
        Return dict in the format
             {"apps": [{"id": <id>, "name": <name>, "description": <description>, "logo": <logo>}, ...]}
        Containing the loaded outbound applications information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_get(
            uri=MgmtV1.outbound_application_load_all_path,
            pswd=self._auth.management_key,
        )
        return response.json()

    def fetch_token_by_scopes(
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
        return _OutboundApplicationTokenFetcher.fetch_token_by_scopes(
            self._auth,
            self._auth.management_key,  # type: ignore[arg-type] # will never get here with None value
            app_id,
            user_id,
            scopes,
            options,
            tenant_id,
        )

    def fetch_token(
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
        return _OutboundApplicationTokenFetcher.fetch_token(
            self._auth,
            self._auth.management_key,  # type: ignore[arg-type] # will never get here with None value
            app_id,
            user_id,
            tenant_id,
            options,
        )

    def fetch_tenant_token_by_scopes(
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
        return _OutboundApplicationTokenFetcher.fetch_tenant_token_by_scopes(
            self._auth,
            self._auth.management_key,  # type: ignore[arg-type] # will never get here with None value
            app_id,
            tenant_id,
            scopes,
            options,
        )

    def fetch_tenant_token(
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
        return _OutboundApplicationTokenFetcher.fetch_tenant_token(
            self._auth,
            self._auth.management_key,  # type: ignore[arg-type] # will never get here with None value
            app_id,
            tenant_id,
            options,
        )

    @staticmethod
    def _compose_create_update_body(
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
        body: dict[str, Any] = {
            "name": name,
            "id": id,
            "description": description,
            "logo": logo,
        }
        if client_secret:
            body["clientSecret"] = client_secret
        if client_id:
            body["clientId"] = client_id
        if discovery_url:
            body["discoveryUrl"] = discovery_url
        if authorization_url:
            body["authorizationUrl"] = authorization_url
        if authorization_url_params is not None:
            body["authorizationUrlParams"] = url_params_to_dict(
                authorization_url_params
            )
        if token_url:
            body["tokenUrl"] = token_url
        if token_url_params is not None:
            body["tokenUrlParams"] = url_params_to_dict(token_url_params)
        if revocation_url:
            body["revocationUrl"] = revocation_url
        if default_scopes is not None:
            body["defaultScopes"] = default_scopes
        if default_redirect_url:
            body["defaultRedirectUrl"] = default_redirect_url
        if callback_domain:
            body["callbackDomain"] = callback_domain
        if pkce is not None:
            body["pkce"] = pkce
        if access_type:
            body["accessType"] = access_type.value
        if prompt is not None:
            body["prompt"] = [p.value for p in prompt]
        return body


class OutboundApplicationByToken(AuthBase):

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

    def fetch_token_by_scopes(
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
        return _OutboundApplicationTokenFetcher.fetch_token_by_scopes(
            self._auth, token, app_id, user_id, scopes, options, tenant_id
        )

    def fetch_token(
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
        return _OutboundApplicationTokenFetcher.fetch_token(
            self._auth, token, app_id, user_id, tenant_id, options
        )

    def fetch_tenant_token_by_scopes(
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
        return _OutboundApplicationTokenFetcher.fetch_tenant_token_by_scopes(
            self._auth, token, app_id, tenant_id, scopes, options
        )

    def fetch_tenant_token(
        self, token: str, app_id: str, tenant_id: str, options: Optional[dict] = None
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
        return _OutboundApplicationTokenFetcher.fetch_tenant_token(
            self._auth, token, app_id, tenant_id, options
        )
