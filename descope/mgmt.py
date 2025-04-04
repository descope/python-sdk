from descope.auth import Auth
from descope.management.access_key import AccessKey  # noqa: F401
from descope.management.audit import Audit  # noqa: F401
from descope.management.authz import Authz  # noqa: F401
from descope.management.fga import FGA  # noqa: F401
from descope.management.flow import Flow  # noqa: F401
from descope.management.group import Group  # noqa: F401
from descope.management.jwt import JWT  # noqa: F401
from descope.management.permission import Permission  # noqa: F401
from descope.management.project import Project  # noqa: F401
from descope.management.role import Role  # noqa: F401
from descope.management.sso_application import SSOApplication  # noqa: F401
from descope.management.sso_settings import SSOSettings  # noqa: F401
from descope.management.tenant import Tenant  # noqa: F401
from descope.management.user import User  # noqa: F401


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

    @property
    def tenant(self):
        return self._tenant

    @property
    def sso_application(self):
        return self._sso_application

    @property
    def user(self):
        return self._user

    @property
    def access_key(self):
        return self._access_key

    @property
    def sso(self):
        return self._sso

    @property
    def jwt(self):
        return self._jwt

    @property
    def permission(self):
        return self._permission

    @property
    def role(self):
        return self._role

    @property
    def group(self):
        return self._group

    @property
    def flow(self):
        return self._flow

    @property
    def audit(self):
        return self._audit

    @property
    def authz(self):
        return self._authz

    @property
    def fga(self):
        return self._fga

    @property
    def project(self):
        return self._project
