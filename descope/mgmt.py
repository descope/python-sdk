from descope.auth import Auth
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException  # noqa: F401
from descope.management.access_key import AccessKey  # noqa: F401
from descope.management.audit import Audit  # noqa: F401
from descope.management.authz import Authz  # noqa: F401
from descope.management.fga import FGA  # noqa: F401
from descope.management.flow import Flow  # noqa: F401
from descope.management.group import Group  # noqa: F401
from descope.management.jwt import JWT  # noqa: F401
from descope.management.outbound_application import (  # noqa: F401  # noqa: F401
    OutboundApplication,
    OutboundApplicationByToken,
)
from descope.management.permission import Permission  # noqa: F401
from descope.management.project import Project  # noqa: F401
from descope.management.role import Role  # noqa: F401
from descope.management.sso_application import SSOApplication  # noqa: F401
from descope.management.sso_settings import SSOSettings  # noqa: F401
from descope.management.tenant import Tenant  # noqa: F401
from descope.management.user import User


class MGMT:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth
        self._tenant = Tenant(auth)
        self._sso_application = SSOApplication(auth)
        self._user = User(auth)
        self._access_key = AccessKey(auth)
        self._sso = SSOSettings(auth)
        self._jwt = JWT(auth)
        self._permission = Permission(auth)
        self._role = Role(auth)
        self._group = Group(auth)
        self._flow = Flow(auth)
        self._audit = Audit(auth)
        self._authz = Authz(auth)
        self._fga = FGA(auth)
        self._project = Project(auth)
        self._outbound_application = OutboundApplication(auth)
        self._outbound_application_by_token = OutboundApplicationByToken(auth)

    def _check_management_key(self, property_name: str):
        """Check if management key is available for the given property."""
        if not self._auth.management_key:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Management key is required to access '{property_name}' functionality",
            )

    @property
    def tenant(self):
        self._check_management_key("tenant")
        return self._tenant

    @property
    def sso_application(self):
        self._check_management_key("sso_application")
        return self._sso_application

    @property
    def user(self):
        self._check_management_key("user")
        return self._user

    @property
    def access_key(self):
        self._check_management_key("access_key")
        return self._access_key

    @property
    def sso(self):
        self._check_management_key("sso")
        return self._sso

    @property
    def jwt(self):
        self._check_management_key("jwt")
        return self._jwt

    @property
    def permission(self):
        self._check_management_key("permission")
        return self._permission

    @property
    def role(self):
        self._check_management_key("role")
        return self._role

    @property
    def group(self):
        self._check_management_key("group")
        return self._group

    @property
    def flow(self):
        self._check_management_key("flow")
        return self._flow

    @property
    def audit(self):
        self._check_management_key("audit")
        return self._audit

    @property
    def authz(self):
        self._check_management_key("authz")
        return self._authz

    @property
    def fga(self):
        self._check_management_key("fga")
        return self._fga

    @property
    def project(self):
        self._check_management_key("project")
        return self._project

    @property
    def outbound_application(self):
        self._check_management_key("outbound_application")
        return self._outbound_application

    @property
    def outbound_application_by_token(self):
        # No management key check for outbound_app_token (as authentication for those methods is done by inbound app token)
        return self._outbound_application_by_token
