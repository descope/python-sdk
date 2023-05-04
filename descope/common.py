from enum import Enum

from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException

DEFAULT_BASE_URL = "https://api.descope.com"  # pragma: no cover
DEFAULT_TIMEOUT_SECONDS = 60

PHONE_REGEX = """^(?:(?:\\(?(?:00|\\+)([1-4]\\d\\d|[1-9]\\d?)\\)?)?[\\-\\.\\ \\\\/]?)?((?:\\(?\\d{1,}\\)?[\\-\\.\\ \\\\/]?){0,})(?:[\\-\\.\\ \\\\/]?(?:#|ext\\.?|extension|x)[\\-\\.\\ \\\\/]?(\\d+))?$"""

SESSION_COOKIE_NAME = "DS"
REFRESH_SESSION_COOKIE_NAME = "DSR"

SESSION_TOKEN_NAME = "sessionToken"
REFRESH_SESSION_TOKEN_NAME = "refreshSessionToken"
COOKIE_DATA_NAME = "cookieData"

REDIRECT_LOCATION_COOKIE_NAME = "Location"


class EndpointsV1:
    refresh_token_path = "/v1/auth/refresh"
    logout_path = "/v1/auth/logout"
    logout_all_path = "/v1/auth/logoutall"
    me_path = "/v1/auth/me"

    # accesskey
    exchange_auth_access_key_path = "/v1/auth/accesskey/exchange"

    # otp
    sign_up_auth_otp_path = "/v1/auth/otp/signup"
    sign_in_auth_otp_path = "/v1/auth/otp/signin"
    sign_up_or_in_auth_otp_path = "/v1/auth/otp/signup-in"
    verify_code_auth_path = "/v1/auth/otp/verify"
    update_user_email_otp_path = "/v1/auth/otp/update/email"
    update_user_phone_otp_path = "/v1/auth/otp/update/phone"

    # magiclink
    sign_up_auth_magiclink_path = "/v1/auth/magiclink/signup"
    sign_in_auth_magiclink_path = "/v1/auth/magiclink/signin"
    sign_up_or_in_auth_magiclink_path = "/v1/auth/magiclink/signup-in"
    verify_magiclink_auth_path = "/v1/auth/magiclink/verify"
    get_session_magiclink_auth_path = "/v1/auth/magiclink/pending-session"
    update_user_email_magiclink_path = "/v1/auth/magiclink/update/email"
    update_user_phone_magiclink_path = "/v1/auth/magiclink/update/phone"

    # enchantedlink
    sign_up_auth_enchantedlink_path = "/v1/auth/enchantedlink/signup"
    sign_in_auth_enchantedlink_path = "/v1/auth/enchantedlink/signin"
    sign_up_or_in_auth_enchantedlink_path = "/v1/auth/enchantedlink/signup-in"
    verify_enchantedlink_auth_path = "/v1/auth/enchantedlink/verify"
    get_session_enchantedlink_auth_path = "/v1/auth/enchantedlink/pending-session"
    update_user_email_enchantedlink_path = "/v1/auth/enchantedlink/update/email"

    # oauth
    oauth_start_path = "/v1/auth/oauth/authorize"
    oauth_exchange_token_path = "/v1/auth/oauth/exchange"

    # saml
    auth_saml_start_path = "/v1/auth/saml/authorize"
    saml_exchange_token_path = "/v1/auth/saml/exchange"

    # totp
    sign_up_auth_totp_path = "/v1/auth/totp/signup"
    verify_totp_path = "/v1/auth/totp/verify"
    update_totp_path = "/v1/auth/totp/update"

    # webauthn
    sign_up_auth_webauthn_start_path = "/v1/auth/webauthn/signup/start"
    sign_up_auth_webauthn_finish_path = "/v1/auth/webauthn/signup/finish"
    sign_in_auth_webauthn_start_path = "/v1/auth/webauthn/signin/start"
    sign_in_auth_webauthn_finish_path = "/v1/auth/webauthn/signin/finish"
    sign_up_or_in_auth_webauthn_start_path = "/v1/auth/webauthn/signup-in/start"
    update_auth_webauthn_start_path = "/v1/auth/webauthn/update/start"
    update_auth_webauthn_finish_path = "/v1/auth/webauthn/update/finish"

    # password
    sign_up_password_path = "/v1/auth/password/signup"
    sign_in_password_path = "/v1/auth/password/signin"
    send_reset_password_path = "/v1/auth/password/reset"
    update_password_path = "/v1/auth/password/update"
    replace_password_path = "/v1/auth/password/replace"
    password_policy_path = "/v1/auth/password/policy"


class EndpointsV2:
    public_key_path = "/v2/keys"


class DeliveryMethod(Enum):
    WHATSAPP = 1
    SMS = 2
    EMAIL = 3


class LoginOptions:
    def __init__(
        self, stepup: bool = False, mfa: bool = False, custom_claims: dict = None
    ):
        self.stepup = stepup
        self.customClaims = custom_claims
        self.mfa = mfa


def validate_refresh_token_provided(
    login_options: LoginOptions = None, refresh_token: str = None
):
    refresh_required = login_options is not None and (
        login_options.mfa or login_options.stepup
    )
    refresh_missing = refresh_token is None or refresh_token == ""
    if refresh_required and refresh_missing:
        raise AuthException(
            400,
            ERROR_TYPE_INVALID_ARGUMENT,
            "Missing refresh token for stepup/mfa",
        )
