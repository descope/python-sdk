import sys
from enum import Enum

from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException

if "unittest" in sys.modules:
    DEFAULT_BASE_URL = "http://127.0.0.1"
else:
    DEFAULT_BASE_URL = "https://api.descope.com"  # pragma: no cover

PHONE_REGEX = """^(?:(?:\\(?(?:00|\\+)([1-4]\\d\\d|[1-9]\\d?)\\)?)?[\\-\\.\\ \\\\/]?)?((?:\\(?\\d{1,}\\)?[\\-\\.\\ \\\\/]?){0,})(?:[\\-\\.\\ \\\\/]?(?:#|ext\\.?|extension|x)[\\-\\.\\ \\\\/]?(\\d+))?$"""

SESSION_COOKIE_NAME = "DS"
REFRESH_SESSION_COOKIE_NAME = "DSR"

SESSION_TOKEN_NAME = "sessionToken"
REFRESH_SESSION_TOKEN_NAME = "refreshSessionToken"
COOKIE_DATA_NAME = "cookieData"

REDIRECT_LOCATION_COOKIE_NAME = "Location"


class EndpointsV1:
    refreshTokenPath = "/v1/auth/refresh"
    logoutPath = "/v1/auth/logout"
    logoutAllPath = "/v1/auth/logoutall"
    mePath = "/v1/auth/me"

    # accesskey
    exchangeAuthAccessKeyPath = "/v1/auth/accesskey/exchange"

    # otp
    signUpAuthOTPPath = "/v1/auth/otp/signup"
    signInAuthOTPPath = "/v1/auth/otp/signin"
    signUpOrInAuthOTPPath = "/v1/auth/otp/signup-in"
    verifyCodeAuthPath = "/v1/auth/otp/verify"
    updateUserEmailOTPPath = "/v1/auth/otp/update/email"
    updateUserPhoneOTPPath = "/v1/auth/otp/update/phone"

    # magiclink
    signUpAuthMagicLinkPath = "/v1/auth/magiclink/signup"
    signInAuthMagicLinkPath = "/v1/auth/magiclink/signin"
    signUpOrInAuthMagicLinkPath = "/v1/auth/magiclink/signup-in"
    verifyMagicLinkAuthPath = "/v1/auth/magiclink/verify"
    getSessionMagicLinkAuthPath = "/v1/auth/magiclink/pending-session"
    updateUserEmailMagicLinkPath = "/v1/auth/magiclink/update/email"
    updateUserPhoneMagicLinkPath = "/v1/auth/magiclink/update/phone"

    # enchantedlink
    signUpAuthEnchantedLinkPath = "/v1/auth/enchantedlink/signup"
    signInAuthEnchantedLinkPath = "/v1/auth/enchantedlink/signin"
    signUpOrInAuthEnchantedLinkPath = "/v1/auth/enchantedlink/signup-in"
    verifyEnchantedLinkAuthPath = "/v1/auth/enchantedlink/verify"
    getSessionEnchantedLinkAuthPath = "/v1/auth/enchantedlink/pending-session"
    updateUserEmailEnchantedLinkPath = "/v1/auth/enchantedlink/update/email"

    # oauth
    oauthStart = "/v1/auth/oauth/authorize"
    oauthExchangeTokenPath = "/v1/auth/oauth/exchange"

    # saml
    authSAMLStart = "/v1/auth/saml/authorize"
    samlExchangeTokenPath = "/v1/auth/saml/exchange"

    # totp
    signUpAuthTOTPPath = "/v1/auth/totp/signup"
    verifyTOTPPath = "/v1/auth/totp/verify"
    updateTOTPPath = "/v1/auth/totp/update"

    # webauthn
    signUpAuthWebauthnStart = "/v1/auth/webauthn/signup/start"
    signUpAuthWebauthnFinish = "/v1/auth/webauthn/signup/finish"
    signInAuthWebauthnStart = "/v1/auth/webauthn/signin/start"
    signInAuthWebauthnFinish = "/v1/auth/webauthn/signin/finish"
    signUpOrInAuthWebauthnStart = "/v1/auth/webauthn/signup-in/start"
    updateAuthWebauthnStart = "/v1/auth/webauthn/update/start"
    updateAuthWebauthnFinish = "/v1/auth/webauthn/update/finish"


class EndpointsV2:
    publicKeyPath = "/v2/keys"


class DeliveryMethod(Enum):
    WHATSAPP = 1
    SMS = 2
    EMAIL = 3


class LoginOptions:
    def __init__(
        self, stepup: bool = False, mfa: bool = False, customClaims: dict = None
    ):
        self.stepup = stepup
        self.customClaims = customClaims
        self.mfa = mfa


def validateRefreshTokenProvided(
    login_options: LoginOptions = None, refresh_token: str = None
):
    refreshRequired = login_options is not None and (
        login_options.mfa or login_options.stepup
    )
    refreshMissing = refresh_token is None or refresh_token == ""
    if refreshRequired and refreshMissing:
        raise AuthException(
            400,
            ERROR_TYPE_INVALID_ARGUMENT,
            "Missing refresh token for stepup/mfa",
        )
