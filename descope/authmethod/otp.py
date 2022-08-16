from descope.auth import Auth
from descope.common import REFRESH_SESSION_COOKIE_NAME, DeliveryMethod, EndpointsV1
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class OTP:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def sign_in(self, method: DeliveryMethod, identifier: str) -> None:
        """
        Sign in (log in) an existing user with the unique identifier you provide. (See 'sign_up' function for an explanation of the
            identifier field.) Provide the DeliveryMethod required for this user. If the identifier value cannot be used for the
            DeliverMethod selected (for example, 'identifier = 4567qq445km' and 'DeliveryMethod = email')

        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code to the user, for example
            email, SMS, or WhatsApp
        identifier (str): The identifier of the user being validated for example phone or email

        Raise:
        AuthException: raised if sign-in operation fails
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
        Sign up (create) a new user using their email or phone number. Choose a delivery method for OTP
            verification, for example email, SMS, or WhatsApp.
            (optional) Include additional user metadata that you wish to preserve.

        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code, for example phone or email
        identifier (str): The identifier of the user being validated
        user (dict) optional: Preserve additional user metadata in the form of
             {"name": "Joe Person", "phone": "2125551212", "email": "joe@somecompany.com"}

        Raise:
        AuthException: raised if sign-up operation fails
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
        Sign_up_or_in lets you handle both sign up and sign in with a single call. Sign-up_or_in will first determine if
            identifier is a new or existing end user. If identifier is new, a new end user user will be created and then
            authenticated using the OTP DeliveryMethod specififed. If identifier exists, the end user will be authenticated
            using the OTP DelieryMethod specified.

        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code, for example phone or email
        identifier (str): The identifier of the user being validated

        Raise:
        AuthException: raised if either the sign_up or sign_in operation fails
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
        Verify the valdity of an OTP code entered by an end user during sign_in or sign_up.
        (This function is not needed if you are using the sign_up_or_in function.

        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code, for example phone or email
        identifier (str): The identifier of the user being validated
        code (str): The authorization code enter by the end user during signup/signin

        Return value (dict):
        Return dict in the format
             {"jwts": [], "user": "", "firstSeen": "", "error": ""}
        Includes all the jwts tokens (session token, refresh token), token claims, and user information

        Raise:
        AuthException: raised if the OTP code is not valid or if token verification failed
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
        Update the email address of an end user, after verifying the authenticity of the end user using OTP.

        Args:
        identifier (str): The identifier of the user who's information is being updated
        email (str): The new email address. If an email address already exists for this end user, it will be overwritten
        refresh_token (str): The session's refresh token (used for verification)

        Raise:
        AuthException: raised if OTP verification fails or if token verification fails
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
        Update the phone number of an existing end user, after verifying the authenticity of the end user using OTP.

        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code, for example phone or email
        identifier (str): The identifier of the user who's information is being updated
        phone (str): The new phone number. If a phone number already exists for this end user, it will be overwritten
        refresh_token (str): The session's refresh token (used for OTP verification)

        Raise:
        AuthException: raised if OTP verification fails or if token verification fails
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
