from __future__ import annotations

from typing import Iterable, Optional, Union

from descope._auth_base import AuthBase
from descope.authmethod._totp_base import TOTPBase
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)


class TOTP(TOTPBase, AuthBase):
    def sign_up(self, login_id: str, user: Optional[dict] = None) -> dict:
        """
        Sign up (create) a new user using their email or phone number.
            (optional) Include additional user metadata that you wish to save.

        Args:
        login_id (str): The login ID of the user being validated
        user (dict) optional: Preserve additional user metadata in the form of,
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
        self._validate_login_id(login_id)

        uri = EndpointsV1.sign_up_auth_totp_path
        body = self._compose_signup_body(login_id, user)
        response = self._http.post(uri, body=body)
        return response.json()

    def sign_in_code(
        self,
        login_id: str,
        code: str,
        login_options: Optional[LoginOptions] = None,
        refresh_token: Optional[str] = None,
        audience: Union[str, None, Iterable[str]] = None,
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
        self._validate_login_id(login_id)
        self._validate_code(code)
        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.verify_totp_path
        body = self._compose_signin_body(login_id, code, login_options)
        response = self._http.post(uri, body=body, pswd=refresh_token)

        resp = response.json()
        return self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience
        )

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
        self._validate_login_id(login_id)
        self._validate_refresh_token(refresh_token)

        uri = EndpointsV1.update_totp_path
        body = self._compose_update_user_body(login_id)
        response = self._http.post(uri, body=body, pswd=refresh_token)
        return response.json()
