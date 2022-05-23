from enum import Enum

DEFAULT_BASE_URI = "http://localhost:8191"
DEFAULT_FETCH_PUBLIC_KEY_URI = "http://localhost:8152"  # will use the same base uri as above once gateway will be available

PHONE_REGEX = """^(?:(?:\\(?(?:00|\\+)([1-4]\\d\\d|[1-9]\\d?)\\)?)?[\\-\\.\\ \\\\/]?)?((?:\\(?\\d{1,}\\)?[\\-\\.\\ \\\\/]?){0,})(?:[\\-\\.\\ \\\\/]?(?:#|ext\\.?|extension|x)[\\-\\.\\ \\\\/]?(\\d+))?$"""

SESSION_COOKIE_NAME = "S"


class EndpointsV1:
    signInAuthOTPPath = "/v1/auth/signin/otp"
    signUpAuthOTPPath = "/v1/auth/signup/otp"
    verifyCodeAuthPath = "/v1/auth/code/verify"
    publicKeyPath = "/v1/keys"


class DeliveryMethod(Enum):
    WHATSAPP = 1
    PHONE = 2
    EMAIL = 3


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
