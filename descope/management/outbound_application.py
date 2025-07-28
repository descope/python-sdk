from typing import Any, List, Optional

from descope._auth_base import AuthBase
from descope.management.common import MgmtV1


class OutboundApplication(AuthBase):
    def create_application(
        self,
        name: str,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        id: Optional[str] = None,
        client_secret: Optional[str] = None,
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
                name, description, logo, id, client_secret
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
                    name, description, logo, id, client_secret
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
        uri = MgmtV1.outbound_application_fetch_token_by_scopes_path
        response = self._auth.do_post(
            uri,
            {
                "appId": app_id,
                "userId": user_id,
                "scopes": scopes,
                "options": options,
                "tenantId": tenant_id,
            },
            pswd=self._auth.management_key,
        )
        return response.json()

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
        uri = MgmtV1.outbound_application_fetch_token_path
        response = self._auth.do_post(
            uri,
            {
                "appId": app_id,
                "userId": user_id,
                "tenantId": tenant_id,
                "options": options,
            },
            pswd=self._auth.management_key,
        )
        return response.json()

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
        uri = MgmtV1.outbound_application_fetch_tenant_token_by_scopes_path
        response = self._auth.do_post(
            uri,
            {
                "appId": app_id,
                "tenantId": tenant_id,
                "scopes": scopes,
                "options": options,
            },
            pswd=self._auth.management_key,
        )
        return response.json()

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
        uri = MgmtV1.outbound_application_fetch_tenant_token_path
        response = self._auth.do_post(
            uri,
            {
                "appId": app_id,
                "tenantId": tenant_id,
                "options": options,
            },
            pswd=self._auth.management_key,
        )
        return response.json()

    @staticmethod
    def _compose_create_update_body(
        name: str,
        description: Optional[str] = None,
        logo: Optional[str] = None,
        id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> dict:
        body: dict[str, Any] = {
            "name": name,
            "id": id,
            "description": description,
            "logo": logo,
        }
        if client_secret:
            body["clientSecret"] = client_secret
        return body
