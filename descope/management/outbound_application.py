from typing import Any, Dict, List, Optional

from descope._auth_base import AuthBase
from descope.management.common import MgmtV1


class OutboundApplication(AuthBase):
    def create_application(
        self,
        name: str,
        client_id: str,
        client_secret: str,
        id: Optional[str] = None,
        description: Optional[str] = None,
        template_id: Optional[str] = None,
        logo: Optional[str] = None,
        discovery_url: Optional[str] = None,
        authorization_url: Optional[str] = None,
        authorization_url_params: Optional[List[Dict[str, str]]] = None,
        token_url: Optional[str] = None,
        token_url_params: Optional[List[Dict[str, str]]] = None,
        revocation_url: Optional[str] = None,
        default_scopes: Optional[List[str]] = None,
        default_redirect_url: Optional[str] = None,
        callback_domain: Optional[str] = None,
        pkce: Optional[bool] = None,
        access_type: Optional[str] = None,
        prompt: Optional[List[str]] = None,
    ) -> dict:
        """
        Create a new outbound application with the given parameters.

        Args:
        name (str): The application's name.
        client_id (str): The OAuth client ID for the external provider.
        client_secret (str): The OAuth client secret for the external provider.
        id (str): Optional application ID.
        description (str): Optional application description.
        template_id (str): Optional template ID for pre-configured providers.
        logo (str): Optional application logo URL.
        discovery_url (str): Optional OIDC discovery URL.
        authorization_url (str): Optional OAuth authorization URL.
        authorization_url_params (List[Dict[str, str]]): Optional authorization URL parameters.
        token_url (str): Optional OAuth token URL.
        token_url_params (List[Dict[str, str]]): Optional token URL parameters.
        revocation_url (str): Optional OAuth revocation URL.
        default_scopes (List[str]): Optional default OAuth scopes.
        default_redirect_url (str): Optional default redirect URL.
        callback_domain (str): Optional callback domain.
        pkce (bool): Optional PKCE support flag.
        access_type (str): Optional access type ("online" or "offline").
        prompt (List[str]): Optional prompt parameters.

        Return value (dict):
        Return dict in the format
             {"app": <outbound application object>}

        Raise:
        AuthException: raised if create operation fails
        """
        uri = MgmtV1.outbound_application_create_path
        response = self._auth.do_post(
            uri,
            OutboundApplication._compose_create_update_body(
                name=name,
                client_id=client_id,
                client_secret=client_secret,
                id=id,
                description=description,
                template_id=template_id,
                logo=logo,
                discovery_url=discovery_url,
                authorization_url=authorization_url,
                authorization_url_params=authorization_url_params,
                token_url=token_url,
                token_url_params=token_url_params,
                revocation_url=revocation_url,
                default_scopes=default_scopes,
                default_redirect_url=default_redirect_url,
                callback_domain=callback_domain,
                pkce=pkce,
                access_type=access_type,
                prompt=prompt,
            ),
            pswd=self._auth.management_key,
        )
        return response.json()

    def update_application(
        self,
        id: str,
        name: str,
        client_id: str,
        client_secret: Optional[str] = None,
        description: Optional[str] = None,
        template_id: Optional[str] = None,
        logo: Optional[str] = None,
        discovery_url: Optional[str] = None,
        authorization_url: Optional[str] = None,
        authorization_url_params: Optional[List[Dict[str, str]]] = None,
        token_url: Optional[str] = None,
        token_url_params: Optional[List[Dict[str, str]]] = None,
        revocation_url: Optional[str] = None,
        default_scopes: Optional[List[str]] = None,
        default_redirect_url: Optional[str] = None,
        callback_domain: Optional[str] = None,
        pkce: Optional[bool] = None,
        access_type: Optional[str] = None,
        prompt: Optional[List[str]] = None,
    ) -> dict:
        """
        Update an existing outbound application with the given parameters. IMPORTANT: All parameters are used as overrides
        to the existing application. Empty fields will override populated fields. Use carefully.

        Args:
        id (str): The ID of the application to update.
        name (str): Updated application name.
        client_id (str): The OAuth client ID for the external provider.
        client_secret (str): Optional OAuth client secret for the external provider.
        description (str): Optional application description.
        template_id (str): Optional template ID for pre-configured providers.
        logo (str): Optional application logo URL.
        discovery_url (str): Optional OIDC discovery URL.
        authorization_url (str): Optional OAuth authorization URL.
        authorization_url_params (List[Dict[str, str]]): Optional authorization URL parameters.
        token_url (str): Optional OAuth token URL.
        token_url_params (List[Dict[str, str]]): Optional token URL parameters.
        revocation_url (str): Optional OAuth revocation URL.
        default_scopes (List[str]): Optional default OAuth scopes.
        default_redirect_url (str): Optional default redirect URL.
        callback_domain (str): Optional callback domain.
        pkce (bool): Optional PKCE support flag.
        access_type (str): Optional access type ("online" or "offline").
        prompt (List[str]): Optional prompt parameters.

        Return value (dict):
        Return dict in the format
             {"app": <outbound application object>}

        Raise:
        AuthException: raised if update operation fails
        """
        uri = MgmtV1.outbound_application_update_path
        response = self._auth.do_post(
            uri,
            {
                "app": OutboundApplication._compose_create_update_body(
                    name=name,
                    client_id=client_id,
                    client_secret=client_secret,
                    id=id,
                    description=description,
                    template_id=template_id,
                    logo=logo,
                    discovery_url=discovery_url,
                    authorization_url=authorization_url,
                    authorization_url_params=authorization_url_params,
                    token_url=token_url,
                    token_url_params=token_url_params,
                    revocation_url=revocation_url,
                    default_scopes=default_scopes,
                    default_redirect_url=default_redirect_url,
                    callback_domain=callback_domain,
                    pkce=pkce,
                    access_type=access_type,
                    prompt=prompt,
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
        id (str): The ID of the application that's to be deleted.

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
        id (str): The ID of the application to load.

        Return value (dict):
        Return dict in the format
             {"app": <outbound application object>}
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
             {"apps": [<outbound application objects>]}
        Containing the loaded outbound applications information.

        Raise:
        AuthException: raised if load operation fails
        """
        response = self._auth.do_get(
            uri=MgmtV1.outbound_application_load_all_path,
            pswd=self._auth.management_key,
        )
        return response.json()

    def fetch_outbound_app_user_token(
        self,
        user_id: str,
        app_id: str,
        scopes: Optional[List[str]] = None,
    ) -> dict:
        """
        Fetch the requested token (if exists) for the given user and outbound application.

        Args:
        user_id (str): The user ID to fetch the token for.
        app_id (str): The outbound application ID.
        scopes (List[str]): Optional requested scopes.

        Return value (dict):
        Return dict containing the token information.

        Raise:
        AuthException: raised if fetch operation fails
        """
        uri = MgmtV1.outbound_application_fetch_user_token_path
        response = self._auth.do_post(
            uri,
            {
                "userId": user_id,
                "appId": app_id,
                "scopes": scopes or [],
            },
            pswd=self._auth.management_key,
        )
        return response.json()

    def delete_outbound_app_token_by_id(
        self,
        token_id: str,
    ):
        """
        Delete the outbound application token for the given ID.

        Args:
        token_id (str): Required token ID to delete.

        Raise:
        AuthException: raised if deletion operation fails
        """
        uri = MgmtV1.outbound_application_delete_token_by_id_path
        self._auth.do_post(uri, {"tokenId": token_id}, pswd=self._auth.management_key)

    def delete_outbound_app_user_tokens(
        self,
        user_id: str,
        app_id: str,
    ):
        """
        Delete all outbound application tokens for the given user.

        Args:
        user_id (str): Required user ID.
        app_id (str): Required application ID.

        Raise:
        AuthException: raised if deletion operation fails
        """
        uri = MgmtV1.outbound_application_delete_user_tokens_path
        self._auth.do_post(
            uri,
            {
                "userId": user_id,
                "appId": app_id,
            },
            pswd=self._auth.management_key,
        )

    @staticmethod
    def _compose_create_update_body(
        name: str,
        client_id: str,
        client_secret: Optional[str] = None,
        id: Optional[str] = None,
        description: Optional[str] = None,
        template_id: Optional[str] = None,
        logo: Optional[str] = None,
        discovery_url: Optional[str] = None,
        authorization_url: Optional[str] = None,
        authorization_url_params: Optional[List[Dict[str, str]]] = None,
        token_url: Optional[str] = None,
        token_url_params: Optional[List[Dict[str, str]]] = None,
        revocation_url: Optional[str] = None,
        default_scopes: Optional[List[str]] = None,
        default_redirect_url: Optional[str] = None,
        callback_domain: Optional[str] = None,
        pkce: Optional[bool] = None,
        access_type: Optional[str] = None,
        prompt: Optional[List[str]] = None,
    ) -> dict:
        body: Dict[str, Any] = {
            "id": id,
            "name": name,
            "description": description,
            "templateId": template_id,
            "clientId": client_id,
            "logo": logo,
            "discoveryUrl": discovery_url,
            "authorizationUrl": authorization_url,
            "authorizationUrlParams": authorization_url_params or [],
            "tokenUrl": token_url,
            "tokenUrlParams": token_url_params or [],
            "revocationUrl": revocation_url,
            "defaultScopes": default_scopes or [],
            "defaultRedirectUrl": default_redirect_url,
            "callbackDomain": callback_domain,
            "pkce": pkce,
            "accessType": access_type,
            "prompt": prompt or [],
        }

        # Only include clientSecret if provided (for security)
        if client_secret is not None:
            body["clientSecret"] = client_secret

        return body
