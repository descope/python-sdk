from typing import Optional

from descope.auth import Auth
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.http_client import HTTPClient
from descope.management.access_key import AccessKey
from descope.management.audit import Audit
from descope.management.authz import Authz
from descope.management.fga import FGA
from descope.management.flow import Flow
from descope.management.group import Group
from descope.management.jwt import JWT
from descope.management.outbound_application import (
    OutboundApplication,
    OutboundApplicationByToken,
)
from descope.management.permission import Permission
from descope.management.project import Project
from descope.management.role import Role
from descope.management.sso_application import SSOApplication
from descope.management.sso_settings import SSOSettings

# Import management modules after adapter to avoid circularities
from descope.management.tenant import Tenant
from descope.management.user import User


class MGMT:
    _http: HTTPClient

    def __init__(
        self, http_client: HTTPClient, auth: Auth, fga_cache_url: Optional[str] = None
    ):
        """Create a management API facade.

        Args:
            http_client: HTTP client to use for all management HTTP calls.
        """
        self._http = http_client
        self._access_key = AccessKey(http_client)
        self._audit = Audit(http_client)
        self._authz = Authz(http_client)
        self._fga = FGA(http_client, fga_cache_url=fga_cache_url)
        self._flow = Flow(http_client)
        self._group = Group(http_client)
        self._jwt = JWT(http_client, auth=auth)
        self._outbound_application = OutboundApplication(http_client)
        self._outbound_application_by_token = OutboundApplicationByToken(http_client)
        self._permission = Permission(http_client)
        self._project = Project(http_client)
        self._role = Role(http_client)
        self._sso = SSOSettings(http_client)
        self._sso_application = SSOApplication(http_client)
        self._tenant = Tenant(http_client)
        self._user = User(http_client)

    def _ensure_management_key(self, property_name: str):
        """Check if management key is available for the given property."""
        if not self._http.management_key:
            raise AuthException(
                error_type=ERROR_TYPE_INVALID_ARGUMENT,
                error_message=f"Management key is required to access '{property_name}' functionality",
            )

    @property
    def tenant(self):
        self._ensure_management_key("tenant")
        return self._tenant

    @property
    def sso_application(self):
        self._ensure_management_key("sso_application")
        return self._sso_application

    @property
    def user(self):
        self._ensure_management_key("user")
        return self._user

    @property
    def access_key(self):
        self._ensure_management_key("access_key")
        return self._access_key

    @property
    def sso(self):
        self._ensure_management_key("sso")
        return self._sso

    @property
    def jwt(self):
        self._ensure_management_key("jwt")
        return self._jwt

    @property
    def permission(self):
        self._ensure_management_key("permission")
        return self._permission

    @property
    def role(self):
        self._ensure_management_key("role")
        return self._role

    @property
    def group(self):
        self._ensure_management_key("group")
        return self._group

    @property
    def flow(self):
        self._ensure_management_key("flow")
        return self._flow

    @property
    def audit(self):
        self._ensure_management_key("audit")
        return self._audit

    @property
    def authz(self):
        self._ensure_management_key("authz")
        return self._authz

    @property
    def fga(self):
        self._ensure_management_key("fga")
        return self._fga

    @property
    def project(self):
        self._ensure_management_key("project")
        return self._project

    @property
    def outbound_application(self):
        self._ensure_management_key("outbound_application")
        return self._outbound_application

    @property
    def outbound_application_by_token(self):
        # No management key check for outbound_app_token (as authentication for those methods is done by inbound app token)
        return self._outbound_application_by_token
