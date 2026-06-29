from typing import Any, Dict, List, Optional


# This is not part of the public API but a code helper
def compose_create_update_body(
    name: str,
    login_page_url: str,
    id: Optional[str] = None,
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
    body: Dict[str, Any] = {
        "name": name,
        "loginPageUrl": login_page_url,
    }
    if id is not None:
        body["id"] = id
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
    return body
