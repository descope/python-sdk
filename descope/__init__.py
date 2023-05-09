from descope.common import (
    COOKIE_DATA_NAME,
    REFRESH_SESSION_COOKIE_NAME,
    REFRESH_SESSION_TOKEN_NAME,
    SESSION_COOKIE_NAME,
    SESSION_TOKEN_NAME,
    DeliveryMethod,
    LoginOptions,
)
from descope.descope_client import DescopeClient
from descope.exceptions import (
    API_RATE_LIMIT_RETRY_AFTER_HEADER,
    ERROR_TYPE_API_RATE_LIMIT,
    AuthException,
    RateLimitException,
)
from descope.management.common import AssociatedTenant
from descope.management.sso_settings import AttributeMapping, RoleMapping

# MT: CI can change this from pyproject.toml
# Also, the git tag and the version in pyproject.toml differ
__version__ = '1.5.0'
