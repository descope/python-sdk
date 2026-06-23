from __future__ import annotations

from typing import Any, List, Optional

from descope.management.common import (
    AccessType,
    PromptType,
    URLParam,
    url_params_to_dict,
)


class OutboundApplicationBase:
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
            body["authorizationUrlParams"] = url_params_to_dict(authorization_url_params)
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
