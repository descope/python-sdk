from descope.auth import Auth
from descope.common import REFRESH_SESSION_COOKIE_NAME, DeliveryMethod, EndpointsV1
from descope.exceptions import ERROR_TYPE_INVALID_PUBLIC_KEY, AuthException


class OTP:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def sign_in(self, method: DeliveryMethod, identifier: str) -> None:
        """
            ???Guy - 
                 1. where do we explain why Descoper would choose sign_in, sign_up, or sign_up_or_in
                 2. Since delivermethod can be phone, email, or whatsapp, I made the relevant texts generic
                 3. confirming that I understand something correctly, 
                      "identifier" can currently be email, phone, or email. And is how the end-user identifies]d themselves to Descope, 
                      "DeliveryMethod" can be any of the 3 listed above, but it can differ from "identifier"
                    e.g. end-user enters phone # for identifictaion, thus identifier=972-54-450=9-0206, but they may only have access to 
                    email, so want to use email as DeliveryMethod. 
            ???
    
        Login (sign-in) an existing user with the uniqeu identifier you provide. (See 'sign_up' function for an explanation of the 
            identifier field.) Provide the DeliveryMethod required for this user. If the identifier value cannot be used for the DeliverMethod
            selected (for example, 'identifier = 4567445km' and 'DeliveryMethod = email') then you must provide the uses here the user is identified by their unique identifier. (see sign-up or sign-in) you have provided when signing up this user. the specified DeliveryMethod for OTP verification. The DeliveryMethod can be different
            from the identifier. For example, an end-user can be identified by their phone number, but use email as their OTP
            DelieryMethod for this verification. 
            
        
        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code to the user, for example
            email, SMS, or WhatsApp
        identifier (str): The identifier of the user being validated for example phone or email

        Raise:
        AuthException: raised if OTP operation fails
        """

        if not self._auth.verify_delivery_method(method, identifier):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                f"Identifier {identifier} does not support delivery method {method}",
            )

        uri = OTP._compose_signin_url(method)
        body = OTP._compose_signin_body(identifier)
        self._auth.do_post(uri, body)

    def sign_up(
        self, method: DeliveryMethod, identifier: str, user: dict = None
    ) -> None:
        """
        Create (sign-up) a new user using their email or phone number. Choose a default delivery method for OTP 
            verification, for exmaple email, SMS, or WhatsApp.
            (optional) Include additional user metadata that you wish to preserve.

        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code, for example phone or email
        identifier (str): The identifier of the user being validated
        user (dict) optional: Preserver additional user metadata in the form of {"name": "", "phone": "", "email": ""}
            ???Guy - Can i make up fiels (lastname, firstname, haircolor, etc.)???

        Raise:
        AuthException: for any case sign up by otp operation failed
        """

        if not self._auth.verify_delivery_method(method, identifier):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                f"Identifier {identifier} is does not support delivery method {method}",
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
        if not self._auth.verify_delivery_method(method, identifier):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                f"Identifier {identifier} does not support delivery method {method}",
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

        if not self._auth.verify_delivery_method(method, identifier):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_PUBLIC_KEY,
                f"Identifier {identifier} does not support delivery method {method}",
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
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Identifier cannot be empty"
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
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Identifier cannot be empty"
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
