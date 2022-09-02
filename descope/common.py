from enum import Enum

DEFAULT_BASE_URL = "https://api.descope.com"

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
    updateAuthWebauthnStart = "/v1/auth/webauthn/update/start"
    updateAuthWebauthnFinish = "/v1/auth/webauthn/update/finish"


class DeliveryMethod(Enum):
    WHATSAPP = 1
    PHONE = 2
    EMAIL = 3


OAuthProviders = ["facebook", "github", "google", "microsoft", "gitlab", "apple"]
