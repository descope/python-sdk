from enum import Enum

DEFAULT_BASE_URI = "http://127.0.0.1:8191"
DEFAULT_FETCH_PUBLIC_KEY_URI = "http://127.0.0.1:8152"  # will use the same base uri as above once gateway will be available

PHONE_REGEX = """^(?:(?:\\(?(?:00|\\+)([1-4]\\d\\d|[1-9]\\d?)\\)?)?[\\-\\.\\ \\\\/]?)?((?:\\(?\\d{1,}\\)?[\\-\\.\\ \\\\/]?){0,})(?:[\\-\\.\\ \\\\/]?(?:#|ext\\.?|extension|x)[\\-\\.\\ \\\\/]?(\\d+))?$"""

SESSION_COOKIE_NAME = "DS"
REFRESH_SESSION_COOKIE_NAME = "DSR"

REDIRECT_LOCATION_COOKIE_NAME = "Location"


class EndpointsV1:
    signInAuthOTPPath = "/v1/auth/signin/otp"
    signUpAuthOTPPath = "/v1/auth/signup/otp"
    verifyCodeAuthPath = "/v1/auth/code/verify"
    signInAuthMagicLinkPath = "/v1/auth/signin/magiclink"
    signUpAuthMagicLinkPath = "/v1/auth/signup/magiclink"
    verifyMagicLinkAuthPath = "/v1/auth/magiclink/verify"
    oauthStart = "/v1/oauth/authorize"
    publicKeyPath = "/v1/keys"
    refreshTokenPath = "/v1/auth/refresh"
    logoutPath = "/v1/auth/logoutall"


class DeliveryMethod(Enum):
    WHATSAPP = 1
    PHONE = 2
    EMAIL = 3


OAuthProviders = ["facebook", "github", "google", "microsoft", "gitlab", "apple"]

