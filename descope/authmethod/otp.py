from descope._auth_base import AuthBase
from descope.auth import Auth
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    DeliveryMethod,
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class OTP(AuthBase):
    def sign_in(
        self,
        method: DeliveryMethod,
        login_id: str,
        login_options: LoginOptions = None,
        refresh_token: str = None,
    ) -> str:
        """
        Sign in (log in) an existing user with the unique login_id you provide. (See 'sign_up' function for an explanation of the
            login_id field.) Provide the DeliveryMethod required for this user. If the login_id value cannot be used for the
            DeliverMethod selected (for example, 'login_id = 4567qq445km' and 'DeliveryMethod = email')

        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code to the user, for example
            email, SMS, or WhatsApp
        login_id (str): The login ID of the user being validated for example phone or email
        login_options (LoginOptions): Optional advanced controls over login parameters
        refresh_token: Optional refresh token is needed for specific login options

        Raise:
        AuthException: raised if sign-in operation fails
        """
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        validate_refresh_token_provided(login_options, refresh_token)

        uri = OTP._compose_signin_url(method)
        body = OTP._compose_signin_body(login_id, login_options)
        response = self._auth.do_post(uri, body, None, refresh_token)
        return Auth.extract_masked_address(response.json(), method)

    def sign_up(self, method: DeliveryMethod, login_id: str, user: dict = None) -> str:
        """
        Sign up (create) a new user using their email or phone number. Choose a delivery method for OTP
            verification, for example email, SMS, or WhatsApp.
            (optional) Include additional user metadata that you wish to preserve.

        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code, for example phone or email
        login_id (str): The login ID of the user being validated
        user (dict) optional: Preserve additional user metadata in the form of
             {"name": "Joe Person", "phone": "2125551212", "email": "joe@somecompany.com"}

        Raise:
        AuthException: raised if sign-up operation fails
        """

        if not user:
            user = {}

        if not self._auth.verify_delivery_method(method, login_id, user):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Login ID {login_id} is not valid by delivery method {method}",
            )

        uri = OTP._compose_signup_url(method)
        body = OTP._compose_signup_body(method, login_id, user)
        response = self._auth.do_post(uri, body)
        return Auth.extract_masked_address(response.json(), method)

    def sign_up_or_in(self, method: DeliveryMethod, login_id: str) -> str:
        """
        Sign_up_or_in lets you handle both sign up and sign in with a single call. Sign-up_or_in will first determine if
            login_id is a new or existing end user. If login_id is new, a new end user user will be created and then
            authenticated using the OTP DeliveryMethod specified. If login_id exists, the end user will be authenticated
            using the OTP DeliveryMethod specified.

        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code, for example phone or email
        login_id (str): The Login ID of the user being validated

        Raise:
        AuthException: raised if either the sign_up or sign_in operation fails
        """
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        uri = OTP._compose_sign_up_or_in_url(method)
        body = OTP._compose_signin_body(login_id)
        response = self._auth.do_post(uri, body)
        return Auth.extract_masked_address(response.json(), method)

    def verify_code(self, method: DeliveryMethod, login_id: str, code: str) -> dict:
        """
        Verify the validity of an OTP code entered by an end user during sign_in or sign_up.
        (This function is not needed if you are using the sign_up_or_in function.

        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code, for example phone or email
        login_id (str): The Login ID of the user being validated
        code (str): The authorization code enter by the end user during signup/signin

        Return value (dict):
        Return dict in the format
             {"jwts": [], "user": "", "firstSeen": "", "error": ""}
        Includes all the jwts tokens (session token, refresh token), token claims, and user information

        Raise:
        AuthException: raised if the OTP code is not valid or if token verification failed
        """
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        uri = OTP._compose_verify_code_url(method)
        body = OTP._compose_verify_code_body(login_id, code)
        response = self._auth.do_post(uri, body, None)

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def update_user_email(
        self,
        login_id: str,
        email: str,
        refresh_token: str,
        add_to_login_ids: bool = False,
        on_merge_use_existing: bool = False,
    ) -> str:
        """
        Update the email address of an end user, after verifying the authenticity of the end user using OTP.

        Args:
        login_id (str): The login ID of the user whose information is being updated
        email (str): The new email address. If an email address already exists for this end user, it will be overwritten
        refresh_token (str): The session's refresh token (used for verification)

        Raise:
        AuthException: raised if OTP verification fails or if token verification fails
        """

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_email(email)

        uri = EndpointsV1.update_user_email_otp_path
        body = OTP._compose_update_user_email_body(
            login_id, email, add_to_login_ids, on_merge_use_existing
        )
        response = self._auth.do_post(uri, body, None, refresh_token)
        return Auth.extract_masked_address(response.json(), DeliveryMethod.EMAIL)

    def update_user_phone(
        self,
        method: DeliveryMethod,
        login_id: str,
        phone: str,
        refresh_token: str,
        add_to_login_ids: bool = False,
        on_merge_use_existing: bool = False,
    ) -> str:
        """
        Update the phone number of an existing end user, after verifying the authenticity of the end user using OTP.

        Args:
        method (DeliveryMethod): The method to use for delivering the OTP verification code, for example phone or email
        login_id (str): The login ID of the user whose information is being updated
        phone (str): The new phone number. If a phone number already exists for this end user, it will be overwritten
        refresh_token (str): The session's refresh token (used for OTP verification)
        add_to_login_ids (bool): Defaults to false, determine whether to add this email to the login ids of hte user or not
        on_merge_use_existing (bool): Defaults to false, In case add_to_login_ids and there is such a user already
            determine whether keep the existing user, or this new one

        Raise:
        AuthException: raised if OTP verification fails or if token verification fails
        """

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        Auth.validate_phone(method, phone)

        uri = OTP._compose_update_phone_url(method)
        body = OTP._compose_update_user_phone_body(
            login_id, phone, add_to_login_ids, on_merge_use_existing
        )
        response = self._auth.do_post(uri, body, None, refresh_token)
        return Auth.extract_masked_address(response.json(), DeliveryMethod.SMS)

    @staticmethod
    def _compose_signup_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.sign_up_auth_otp_path, method)

    @staticmethod
    def _compose_signin_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.sign_in_auth_otp_path, method)

    @staticmethod
    def _compose_sign_up_or_in_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.sign_up_or_in_auth_otp_path, method)

    @staticmethod
    def _compose_verify_code_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.verify_code_auth_path, method)

    @staticmethod
    def _compose_update_phone_url(method: DeliveryMethod) -> str:
        return Auth.compose_url(EndpointsV1.update_user_phone_otp_path, method)

    @staticmethod
    def _compose_signup_body(method: DeliveryMethod, login_id: str, user: dict) -> dict:
        body = {"loginId": login_id}

        if user is not None:
            body["user"] = user
            method_str, val = Auth.get_login_id_by_method(method, user)
            body[method_str] = val
        return body

    @staticmethod
    def _compose_signin_body(login_id: str, login_options: LoginOptions = None) -> dict:
        return {
            "loginId": login_id,
            "loginOptions": login_options.__dict__ if login_options else {},
        }

    @staticmethod
    def _compose_verify_code_body(login_id: str, code: str) -> dict:
        return {"loginId": login_id, "code": code}

    @staticmethod
    def _compose_update_user_email_body(
        login_id: str, email: str, add_to_login_ids: bool, on_merge_use_existing: bool
    ) -> dict:
        return {
            "loginId": login_id,
            "email": email,
            "addToLoginIDs": add_to_login_ids,
            "onMergeUseExisting": on_merge_use_existing,
        }

    @staticmethod
    def _compose_update_user_phone_body(
        login_id: str, phone: str, add_to_login_ids: bool, on_merge_use_existing: bool
    ) -> dict:
        return {
            "loginId": login_id,
            "phone": phone,
            "addToLoginIDs": add_to_login_ids,
            "onMergeUseExisting": on_merge_use_existing,
        }
