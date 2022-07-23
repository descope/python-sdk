from enum import Enum

DEFAULT_BASE_URI = "http://127.0.0.1:8191"
DEFAULT_FETCH_PUBLIC_KEY_URI = "http://127.0.0.1:8152"  # will use the same base uri as above once gateway will be available

PHONE_REGEX = """^(?:(?:\\(?(?:00|\\+)([1-4]\\d\\d|[1-9]\\d?)\\)?)?[\\-\\.\\ \\\\/]?)?((?:\\(?\\d{1,}\\)?[\\-\\.\\ \\\\/]?){0,})(?:[\\-\\.\\ \\\\/]?(?:#|ext\\.?|extension|x)[\\-\\.\\ \\\\/]?(\\d+))?$"""

SESSION_COOKIE_NAME = "DS"
REFRESH_SESSION_COOKIE_NAME = "DSR"

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
    updateUserEmailMagicLinkPath = "/v1/user/update/email/magiclink"
    updateUserPhoneMagicLinkPath = "/v1/user/update/phone/magiclink"

    # oauth
    oauthStart = "/v1/oauth/authorize"

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

    # saml
    authSAMLStart = "/v1/auth/saml/authorize"


class DeliveryMethod(Enum):
    WHATSAPP = 1
    PHONE = 2
    EMAIL = 3


OAuthProviders = ["facebook", "github", "google", "microsoft", "gitlab", "apple"]
