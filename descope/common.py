from enum import Enum

DEFAULT_BASE_URI = "https://localhost:8443"
DEFAULT_FETCH_PUBLIC_KEY_URI = "https://localhost:8443"  # will use the same base uri as above once gateway will be available

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


class User:
    def __init__(self, username: str, name: str, phone: str, email: str):
        self.username = username
        self.name = name
        self.phone = phone
        self.email = email

    def get_data(self):
        return {
            "username": self.username,
            "name": self.name,
            "phone": self.phone,
            "email": self.email,
        }
