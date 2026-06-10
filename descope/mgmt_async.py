from typing import Optional

from descope.auth import Auth
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.http_client_async import HTTPClientAsync
from descope.management.access_key_async import AccessKeyAsync
from descope.management.audit_async import AuditAsync
from descope.management.authz_async import AuthzAsync
from descope.management.descoper_async import DescoperAsync
from descope.management.fga_async import FGAAsync
from descope.management.flow_async import FlowAsync
from descope.management.group_async import GroupAsync
from descope.management.jwt_async import JWTAsync
from descope.management.license_async import LicenseAsync
from descope.management.management_key_async import ManagementKeyAsync
from descope.management.outbound_application_async import (
    OutboundApplicationAsync,
    OutboundApplicationByTokenAsync,
)
from descope.management.permission_async import PermissionAsync
from descope.management.project_async import ProjectAsync
from descope.management.role_async import RoleAsync
from descope.management.sso_application_async import SSOApplicationAsync
from descope.management.sso_settings_async import SSOSettingsAsync

# Import management modules after adapter to avoid circularities
from descope.management.tenant_async import TenantAsync
from descope.management.user_async import UserAsync


class MGMTAsync:
    _http: HTTPClientAsync

    def __init__(self, http_client: HTTPClientAsync, auth: Auth, fga_cache_url: Optional[str] = None):
        """Create an async management API facade.

        Args:
            http_client: Async HTTP client to use for all management HTTP calls.
        """
        self._http = http_client
        self._access_key = AccessKeyAsync(http_client)
        self._audit = AuditAsync(http_client)
        self._authz = AuthzAsync(http_client, fga_cache_url=fga_cache_url)
        self._descoper = DescoperAsync(http_client)
        self._fga = FGAAsync(http_client, fga_cache_url=fga_cache_url)
        self._flow = FlowAsync(http_client)
        self._group = GroupAsync(http_client)
        self._jwt = JWTAsync(http_client, auth=auth)
        self._license = LicenseAsync(http_client)
        self._management_key = ManagementKeyAsync(http_client)
        self._outbound_application = OutboundApplicationAsync(http_client)
        self._outbound_application_by_token = OutboundApplicationByTokenAsync(http_client)
        self._permission = PermissionAsync(http_client)
        self._project = ProjectAsync(http_client)
        self._role = RoleAsync(http_client)
        self._sso = SSOSettingsAsync(http_client)
        self._sso_application = SSOApplicationAsync(http_client)
        self._tenant = TenantAsync(http_client)
        self._user = UserAsync(http_client)

    def _ensure_management_key(self, property_name: str):
        """Check if management key is available for the given property."""
        if not self._http.management_key:
            raise AuthException(
                error_type=ERROR_TYPE_INVALID_ARGUMENT,
                error_message=f"Management key is required to access '{property_name}' functionality",
            )

    @property
    def tenant(self) -> TenantAsync:
        self._ensure_management_key("tenant")
        return self._tenant

    @property
    def sso_application(self) -> SSOApplicationAsync:
        self._ensure_management_key("sso_application")
        return self._sso_application

    @property
    def user(self) -> UserAsync:
        self._ensure_management_key("user")
        return self._user

    @property
    def access_key(self) -> AccessKeyAsync:
        self._ensure_management_key("access_key")
        return self._access_key

    @property
    def sso(self) -> SSOSettingsAsync:
        self._ensure_management_key("sso")
        return self._sso

    @property
    def jwt(self) -> JWTAsync:
        self._ensure_management_key("jwt")
        return self._jwt

    @property
    def license(self) -> LicenseAsync:
        self._ensure_management_key("license")
        return self._license

    @property
    def permission(self) -> PermissionAsync:
        self._ensure_management_key("permission")
        return self._permission

    @property
    def role(self) -> RoleAsync:
        self._ensure_management_key("role")
        return self._role

    @property
    def group(self) -> GroupAsync:
        self._ensure_management_key("group")
        return self._group

    @property
    def flow(self) -> FlowAsync:
        self._ensure_management_key("flow")
        return self._flow

    @property
    def audit(self) -> AuditAsync:
        self._ensure_management_key("audit")
        return self._audit

    @property
    def authz(self) -> AuthzAsync:
        self._ensure_management_key("authz")
        return self._authz

    @property
    def fga(self) -> FGAAsync:
        self._ensure_management_key("fga")
        return self._fga

    @property
    def project(self) -> ProjectAsync:
        self._ensure_management_key("project")
        return self._project

    @property
    def outbound_application(self) -> OutboundApplicationAsync:
        self._ensure_management_key("outbound_application")
        return self._outbound_application

    @property
    def outbound_application_by_token(self) -> OutboundApplicationByTokenAsync:
        # No management key check for outbound_app_token (as authentication for those methods is done by inbound app token)
        return self._outbound_application_by_token

    @property
    def descoper(self) -> DescoperAsync:
        self._ensure_management_key("descoper")
        return self._descoper

    @property
    def management_key(self) -> ManagementKeyAsync:
        self._ensure_management_key("management_key")
        return self._management_key
