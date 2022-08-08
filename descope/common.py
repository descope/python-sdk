from enum import Enum

DEFAULT_BASE_URL = "https://descope.com"  # "http://127.0.0.1:8191"
DEFAULT_FETCH_PUBLIC_KEY_URI = "http://127.0.0.1:8152"

PHONE_REGEX = """^(?:(?:\\(?(?:00|\\+)([1-4]\\d\\d|[1-9]\\d?)\\)?)?[\\-\\.\\ \\\\/]?)?((?:\\(?\\d{1,}\\)?[\\-\\.\\ \\\\/]?){0,})(?:[\\-\\.\\ \\\\/]?(?:#|ext\\.?|extension|x)[\\-\\.\\ \\\\/]?(\\d+))?$"""

SESSION_COOKIE_NAME = "DS"
REFRESH_SESSION_COOKIE_NAME = "DSR"

SESSION_TOKEN_NAME = "sessionToken"
REFRESH_SESSION_TOKEN_NAME = "refreshSessionToken"
COOKIE_DATA_NAME = "cookieData"

REDIRECT_LOCATION_COOKIE_NAME = "Location"


class EndpointsV1:
    publicKeyPath = "/v1/keys"
    refreshTokenPath = "/v1/auth/refresh"
    logoutPath = "/v1/auth/logoutall"

    # otp
    signUpAuthOTPPath = "/v1/auth/signup/otp"
    signInAuthOTPPath = "/v1/auth/signin/otp"
    signUpOrInAuthOTPPath = "/v1/auth/sign-up-or-in/otp"
    verifyCodeAuthPath = "/v1/auth/code/verify"
    updateUserEmailOTPPath = "/v1/user/update/email/otp"
    updateUserPhoneOTPPath = "/v1/user/update/phone/otp"

    # magiclink
    signUpAuthMagicLinkPath = "/v1/auth/signup/magiclink"
    signInAuthMagicLinkPath = "/v1/auth/signin/magiclink"
    signUpOrInAuthMagicLinkPath = "/v1/auth/sign-up-or-in/magiclink"
    verifyMagicLinkAuthPath = "/v1/auth/magiclink/verify"
    getSessionMagicLinkAuthPath = "/v1/auth/magiclink/session"
    updateUserEmailMagicLinkPath = "/v1/user/update/email/magiclink"
    updateUserPhoneMagicLinkPath = "/v1/user/update/phone/magiclink"

    # oauth
    oauthStart = "/v1/oauth/authorize"

    # saml
    authSAMLStart = "/v1/auth/saml/authorize"

    # exchange (saml + oauth)
    exchangeTokenPath = "/v1/auth/exchange"

    # totp
    signUpAuthTOTPPath = "/v1/auth/signup/totp"
    verifyTOTPPath = "/v1/auth/verify/totp"
    updateTOTPPath = "/v1/user/update/totp"

    # webauthn
    signUpAuthWebauthnStart = "/v1/webauthn/signup/start"
    signUpAuthWebauthnFinish = "/v1/webauthn/signup/finish"
    signInAuthWebauthnStart = "/v1/webauthn/signin/start"
    signInAuthWebauthnFinish = "/v1/webauthn/signin/finish"
    deviceAddAuthWebauthnStart = "/v1/webauthn/device/add/start"
    deviceAddAuthWebauthnFinish = "/v1/webauthn/device/add/finish"


class DeliveryMethod(Enum):
    WHATSAPP = 1
    PHONE = 2
    EMAIL = 3


OAuthProviders = ["facebook", "github", "google", "microsoft", "gitlab", "apple"]
