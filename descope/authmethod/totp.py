from descope.auth import Auth
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
    validateRefreshTokenProvided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class TOTP:
    _auth: Auth

    def __init__(self, auth):
        self._auth = auth

    def sign_up(self, login_id: str, user: dict = None) -> dict:
        """
        Sign up (create) a new user using their email or phone number.
            (optional) Include additional user metadata that you wish to save.

        Args:
        login_id (str): The login ID of the user being validated
        user (dict) optional: Preserve additional user metadata in the form of
             {"name": "Desmond Copeland", "phone": "2125551212", "email": "des@cope.com"}

        Return value (dict):
        Return dict in the format
             {"provisioningURL": "", "image": "", "key": ""}
        Includes 3 different ways to allow the user to save their credentials in
        their authenticator app, either by clicking the provisioning URL, scanning the QR
        image or inserting the key manually.

        Raise:
        AuthException: raised if sign-up operation fails
        """

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        uri = EndpointsV1.signUpAuthTOTPPath
        body = TOTP._compose_signup_body(login_id, user)
        response = self._auth.do_post(uri, body)

        return response.json()

    def sign_in_code(
        self,
        login_id: str,
        code: str,
        login_options: LoginOptions = None,
        refresh_token: str = None,
    ) -> dict:
        """
        Sign in by verifying the validity of a TOTP code entered by an end user.

        Args:
        login_id (str): The login ID of the user being validated
        code (str): The authenticator app code provided by the end user
        login_options (LoginOptions): Optional advanced controls over login parameters
        refresh_token: Optional refresh token is needed for specific login options

        Return value (dict):
        Return dict in the format
             {"jwts": [], "user": "", "firstSeen": "", "error": ""}
        Includes all the jwts tokens (session token, refresh token), token claims, and user information

        Raise:
        AuthException: raised if the TOTP code is not valid or if code verification failed
        """

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        if not code:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Code cannot be empty"
            )

        validateRefreshTokenProvided(login_options, refresh_token)

        uri = EndpointsV1.verifyTOTPPath
        body = TOTP._compose_signin_body(login_id, code, login_options)
        response = self._auth.do_post(uri, body, None, refresh_token)

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def update_user(self, login_id: str, refresh_token: str) -> None:
        """
        Add TOTP to an existing logged in user using their refresh token.

        Args:
        login_id (str): The login ID of the user whose information is being updated
        refresh_token (str): The session's refresh token (used for verification)

        Return value (dict):
        Return dict in the format
             {"provisioningURL": "", "image": "", "key": ""}
        Includes 3 different ways to allow the user to save their credentials in
        their authenticator app, either by clicking the provisioning URL, scanning the QR
        image or inserting the key manually.

        Raise:
        AuthException: raised if refresh token is invalid or update operation fails
        """

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty"
            )

        if not refresh_token:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Refresh token cannot be empty"
            )

        uri = EndpointsV1.updateTOTPPath
        body = TOTP._compose_update_user_body(login_id)
        response = self._auth.do_post(uri, body, None, refresh_token)

        return response.json()

    @staticmethod
    def _compose_signup_body(login_id: str, user: dict) -> dict:
        body = {"loginId": login_id}
        if user is not None:
            body["user"] = user
        return body

    @staticmethod
    def _compose_signin_body(
        login_id: str, code: str, login_options: LoginOptions = None
    ) -> dict:
        return {
            "loginId": login_id,
            "code": code,
            "loginOptions": login_options.__dict__ if login_options else {},
        }

    @staticmethod
    def _compose_update_user_body(login_id: str) -> dict:
        return {"loginId": login_id}
