from __future__ import annotations

import logging
import os
import warnings
from typing import Iterable

import httpx

from descope.auth import Auth
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.http_client import HTTPClient
from descope.management.common import MgmtV1

logger = logging.getLogger(__name__)

LICENSE_HANDSHAKE_TIMEOUT_SECONDS = 5.0


class DescopeClientBase:
    """
    Shared base for DescopeClient and DescopeClientAsync.

    Handles:
    - project_id validation and skip_verify warning
    - Auth construction (via a sync HTTPClient for the one-time key fetch)
    - All pure-computation validation helpers (no I/O)
    """

    def __init__(
        self,
        project_id: str,
        public_key: dict | None,
        skip_verify: bool,
        timeout_seconds: float,
        jwt_validation_leeway: int,
        auth_management_key: str | None,
        *,
        base_url: str | None,
        verbose: bool,
    ):
        project_id = project_id or os.getenv("DESCOPE_PROJECT_ID", "")
        if not project_id:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                (
                    "Unable to init client because project_id cannot be empty. "
                    "Set environment variable DESCOPE_PROJECT_ID or pass your Project ID to the init function."
                ),
            )

        if skip_verify:
            warnings.warn(
                "⚠️  SECURITY WARNING: TLS certificate verification is DISABLED (skip_verify=True). "
                "This makes your application vulnerable to man-in-the-middle attacks. "
                "ONLY use this for local development with self-signed certificates. "
                "NEVER use skip_verify=True in production environments.",
                category=UserWarning,
                # stacklevel 3: warn → base.__init__ → subclass.__init__ → user code
                stacklevel=3,
            )

        _auth_http = HTTPClient(
            project_id=project_id,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            secure=not skip_verify,
            management_key=auth_management_key or os.getenv("DESCOPE_AUTH_MANAGEMENT_KEY"),
            verbose=verbose,
        )
        self._auth = Auth(project_id, public_key, jwt_validation_leeway, http_client=_auth_http)

    # -------------------------------------------------------------------------
    # Argument-validation guards — reused by both DescopeClient and DescopeClientAsync
    # -------------------------------------------------------------------------

    @staticmethod
    def _ensure_present(value, message: str, error_type: str = ERROR_TYPE_INVALID_ARGUMENT) -> None:
        """Raise AuthException(400, error_type, message) if *value* is falsy."""
        if not value:
            raise AuthException(400, error_type, message)

    @staticmethod
    def _require_refresh_token(refresh_token) -> None:
        """Guard for ops that act on a refresh token (logout, me, history, my_tenants).

        Uses an ``is None`` check (not falsy) to preserve the historical error
        message that echoes the token value.
        """
        if refresh_token is None:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"signed refresh token {refresh_token} is empty",
            )

    @staticmethod
    def _require_access_key(access_key) -> None:
        """Guard for exchange_access_key."""
        if not access_key:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Access key cannot be empty")

    @staticmethod
    def _validate_tenant_selector(dct: bool, ids) -> None:
        """Guard for my_tenants: exactly one of *dct* or *ids* must be supplied."""
        if dct is True and ids is not None and len(ids) > 0:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Only one of 'dct' or 'ids' should be supplied")
        if dct is False and (ids is None or len(ids) == 0):
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Only one of 'dct' or 'ids' should be supplied")

    def _fetch_rate_limit_tier(self, mgmt_http) -> None:
        """Sync license handshake so the x-descope-license header is ready for the first mgmt call."""
        try:
            response = httpx.get(
                f"{mgmt_http.base_url}{MgmtV1.license_get_path}",
                headers={"Authorization": f"Bearer {mgmt_http.project_id}:{mgmt_http.management_key}"},
                follow_redirects=True,
                verify=mgmt_http.client_verify,
                timeout=LICENSE_HANDSHAKE_TIMEOUT_SECONDS,
            )
            if not response.is_success:
                logger.warning(
                    "License handshake returned non-success status %s",
                    response.status_code,
                )
                return
            tier = response.json().get("rateLimitTier")
            if tier:
                mgmt_http.rate_limit_tier = tier
        except Exception as e:
            logger.warning("License handshake failed: %s", e)

    # -------------------------------------------------------------------------
    # Pure sync helpers — no I/O
    # -------------------------------------------------------------------------

    def validate_session(self, session_token: str, audience: Iterable[str] | str | None = None) -> dict:
        """
        Validate a session token. Pure CPU — no network I/O.
        Call this for every incoming request to private endpoints.
        """
        return self._auth.validate_session(session_token, audience)

    def validate_permissions(self, jwt_response: dict, permissions: list[str]) -> bool:
        """
        Validate that jwt_response has been granted the specified permissions.
        For multi-tenant use validate_tenant_permissions.
        """
        return self.validate_tenant_permissions(jwt_response, "", permissions)

    def get_matched_permissions(self, jwt_response: dict, permissions: list[str]) -> list[str]:
        """Return the subset of permissions that jwt_response has been granted."""
        return self.get_matched_tenant_permissions(jwt_response, "", permissions)

    def validate_tenant_permissions(self, jwt_response: dict, tenant: str, permissions: list[str]) -> bool:
        """
        Validate that jwt_response has been granted the specified permissions on tenant.
        Returns True only if all permissions are granted.
        """
        if not jwt_response:
            return False

        if isinstance(permissions, str):
            permissions = [permissions]

        granted = []
        if tenant == "":
            granted = jwt_response.get("permissions", [])
        else:
            if tenant not in jwt_response.get("tenants", {}):
                return False
            granted = jwt_response.get("tenants", {}).get(tenant, {}).get("permissions", [])

        return all(p in granted for p in permissions)

    def get_matched_tenant_permissions(self, jwt_response: dict, tenant: str, permissions: list[str]) -> list[str]:
        """Return the subset of permissions that jwt_response has been granted on tenant."""
        if not jwt_response:
            return []

        if isinstance(permissions, str):
            permissions = [permissions]

        if tenant != "" and tenant not in jwt_response.get("tenants", {}):
            return []

        granted = (
            jwt_response.get("permissions", [])
            if tenant == ""
            else jwt_response.get("tenants", {}).get(tenant, {}).get("permissions", [])
        )
        return [p for p in permissions if p in granted]

    def validate_roles(self, jwt_response: dict, roles: list[str]) -> bool:
        """
        Validate that jwt_response has been granted the specified roles.
        For multi-tenant use validate_tenant_roles.
        """
        return self.validate_tenant_roles(jwt_response, "", roles)

    def get_matched_roles(self, jwt_response: dict, roles: list[str]) -> list[str]:
        """Return the subset of roles that jwt_response has been granted."""
        return self.get_matched_tenant_roles(jwt_response, "", roles)

    def validate_tenant_roles(self, jwt_response: dict, tenant: str, roles: list[str]) -> bool:
        """
        Validate that jwt_response has been granted the specified roles on tenant.
        Returns True only if all roles are granted.
        """
        if not jwt_response:
            return False

        if isinstance(roles, str):
            roles = [roles]

        granted = []
        if tenant == "":
            granted = jwt_response.get("roles", [])
        else:
            if tenant not in jwt_response.get("tenants", {}):
                return False
            granted = jwt_response.get("tenants", {}).get(tenant, {}).get("roles", [])

        return all(r in granted for r in roles)

    def get_matched_tenant_roles(self, jwt_response: dict, tenant: str, roles: list[str]) -> list[str]:
        """Return the subset of roles that jwt_response has been granted on tenant."""
        if not jwt_response:
            return []

        if isinstance(roles, str):
            roles = [roles]

        if tenant != "" and tenant not in jwt_response.get("tenants", {}):
            return []

        granted = (
            jwt_response.get("roles", [])
            if tenant == ""
            else jwt_response.get("tenants", {}).get(tenant, {}).get("roles", [])
        )
        return [r for r in roles if r in granted]
