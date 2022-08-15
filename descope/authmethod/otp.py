from descope.auth import Auth
from descope.common import REFRESH_SESSION_COOKIE_NAME, DeliveryMethod, EndpointsV1
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class OTP:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def sign_in(self, method: DeliveryMethod, identifier: str) -> None:
        """
        Use to login a user based on the given identifier either email or a phone
            and choose the selected delivery method for verification.

        Args:
        method (DeliveryMethod): The OTP method you would like to verify the code
        sent to you (by the same delivery method)

        identifier (str): The identifier will be used for validation can be either email or phone

        Raise:
        AuthException: for any case sign up by otp operation failed
        """
        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        uri = OTP._compose_signin_url(method)
        body = OTP._compose_signin_body(identifier)
        self._auth.do_post(uri, body)

    def sign_up(
        self, method: DeliveryMethod, identifier: str, user: dict = None
    ) -> None:
        """
        Use to create a new user based on the given identifier either email or a phone.
            choose the selected delivery method for verification.
            optional to add user metadata for farther user details such as name and more.

        Args:
        method (DeliveryMethod): The OTP method you would like to verify the code
        sent to you (by the same delivery method)

        identifier (str): The identifier will be used for validation can be either email or phone

        user (dict) optional: User metadata in the form of {"name": "", "phone": "", "email": ""}

        Raise:
        AuthException: for any case sign up by otp operation failed
        """

        if not self._auth.verify_delivery_method(method, identifier, user):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Identifier {identifier} is not valid by delivery method {method}",
            )

        uri = OTP._compose_signup_url(method)
        body = OTP._compose_signup_body(method, identifier, user)
        self._auth.do_post(uri, body)

    def sign_up_or_in(self, method: DeliveryMethod, identifier: str) -> None:
        """
        Use to login in using identifier, if user does not exists, a new user will be created
            with the given identifier.

        Args:
        method (DeliveryMethod): The OTP method you would like to verify the code
        sent to you (by the same delivery method)

        identifier (str): The identifier will be used for validation can be either email or phone

        Raise:
        AuthException: for any case sign up by otp operation failed
        """
        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        uri = OTP._compose_sign_up_or_in_url(method)
        body = OTP._compose_signin_body(identifier)
        self._auth.do_post(uri, body)

    def verify_code(self, method: DeliveryMethod, identifier: str, code: str) -> dict:
        """
        Use to verify a SignIn/SignUp based on the given identifier either an email or a phone
            followed by the code used to verify and authenticate the user.

        Args:
        method (DeliveryMethod): The OTP method you would like to verify the code
        sent to you (by the same delivery method)

        identifier (str): The identifier will be used for validation can be either email or phone

        code (str): The authorization code you get by the delivery method during signup/signin

        Return value (dict):
        Return dict of the form {"jwts": [], "user": "", "firstSeen": "", "error": ""}
        Includes all the jwts tokens (session token, session refresh token) and their claims and user info

        Raise:
        AuthException: for any case code is not valid or tokens verification failed
        """
        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        uri = OTP._compose_verify_code_url(method)
        body = OTP._compose_verify_code_body(identifier, code)
        response = self._auth.do_post(uri, body)

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def update_user_email(
        self, identifier: str, email: str, refresh_token: str
    ) -> None:
        """
        Use to a update email, and verify via OTP

        Args:
        identifier (str): The identifier will be used for validation can be either email or phone

        email (str): The email address to update for the identifier

        refresh_token (str): The refresh session token (used for verification)

        Raise:
        AuthException: for any case code is not valid or tokens verification failed
        """
        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_email(email)

        uri = EndpointsV1.updateUserEmailOTPPath
        body = OTP._compose_update_user_email_body(identifier, email)
        self._auth.do_post(uri, body, refresh_token)

    def update_user_phone(
        self, method: DeliveryMethod, identifier: str, phone: str, refresh_token: str
    ) -> None:
        """
        Use to update phone and validate via OTP allowed methods
        are phone based methods - whatsapp and SMS

        Args:
        method (DeliveryMethod): The OTP method you would like to verify the code
        sent to you (by the same delivery method)

        identifier (str): The identifier will be used for validation can be either email or phone

        phone (str): The phone to update for the identifier

        refresh_token (str): The refresh session token (used for verification)

        Raise:
        AuthException: for any case code is not valid or tokens verification failed
        """
        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_phone(method, phone)

        uri = OTP._compose_update_phone_url(method)
        body = OTP._compose_update_user_phone_body(identifier, phone)
        self._auth.do_post(uri, body, refresh_token)

    @staticmethod
    def _compose_signup_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.signUpAuthOTPPath, method)

    @staticmethod
    def _compose_signin_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.signInAuthOTPPath, method)

    @staticmethod
    def _compose_sign_up_or_in_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.signUpOrInAuthOTPPath, method)

    @staticmethod
    def _compose_verify_code_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.verifyCodeAuthPath, method)

    @staticmethod
    def _compose_update_phone_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.updateUserPhoneOTPPath, method)

    @staticmethod
    def _compose_signup_body(
        method: DeliveryMethod, identifier: str, user: dict
    ) -> dict:
        body = {"externalId": identifier}

        if user is not None:
            body["user"] = user
            method_str, val = Auth.get_identifier_by_method(method, user)
            body[method_str] = val
        return body

    @staticmethod
    def _compose_signin_body(identifier: str) -> dict:
        return {"externalId": identifier}

    @staticmethod
    def _compose_verify_code_body(identifier: str, code: str) -> dict:
        return {"externalId": identifier, "code": code}

    @staticmethod
    def _compose_update_user_email_body(identifier: str, email: str) -> dict:
        return {"externalId": identifier, "email": email}

    @staticmethod
    def _compose_update_user_phone_body(identifier: str, phone: str) -> dict:
        return {"externalId": identifier, "phone": phone}
