from __future__ import annotations

from typing import Iterable

from descope._auth_base import AuthBase
from descope.common import REFRESH_SESSION_COOKIE_NAME, EndpointsV1
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class Password(AuthBase):
    def sign_up(
        self,
        login_id: str,
        password: str,
        user: dict | None = None,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        """
        Sign up (create) a new user using a login ID and password.
            (optional) Include additional user metadata that you wish to save.

        Args:
        login_id (str): The login ID of the user being signed up
        password (str): The new user's password
        user (dict) optional: Preserve additional user metadata in the form of
             {"name": "Desmond Copeland", "phone": "2125551212", "email": "des@cope.com"}

        Return value (dict):
        Return dict in the format
             {"jwts": [], "user": "", "firstSeen": "", "error": ""}
        Includes all the jwts tokens (session token, refresh token), token claims, and user information

        Raise:
        AuthException: raised if sign-up operation fails
        """

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty"
            )

        if not password:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "password cannot be empty"
            )

        uri = EndpointsV1.sign_up_password_path
        body = Password._compose_signup_body(login_id, password, user)
        response = self._http.post(uri, body=body)

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience
        )
        return jwt_response

    def sign_in(
        self,
        login_id: str,
        password: str,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        """
        Sign in by verifying the validity of a password entered by an end user.

        Args:
        login_id (str): The login ID of the user being validated
        password (str): The password to be validated

        Return value (dict):
        Return dict in the format
             {"jwts": [], "user": "", "firstSeen": "", "error": ""}
        Includes all the jwts tokens (session token, refresh token), token claims, and user information

        Raise:
        AuthException: raised if sign in operation fails
        """

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty"
            )

        if not password:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Password cannot be empty"
            )

        uri = EndpointsV1.sign_in_password_path
        response = self._http.post(
            uri, body={"loginId": login_id, "password": password}
        )

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience
        )
        return jwt_response

    def send_reset(
        self,
        login_id: str,
        redirect_url: str | None = None,
        template_options: dict | None = None,
    ) -> dict:
        """
        Sends a password reset prompt to the user with the given
            login_id according to the password settings defined in the Descope console.
            NOTE: The user must be verified according to the configured password reset method.

        Args:
        login_id (str): The login ID of the user to receive a password reset prompt
        redirect_url (str): Optional parameter that is used by Magic Link or Enchanted Link
                if those are the chosen reset methods. See the Magic Link and Enchanted Link sections
                for more details.

        Return value (dict):
        Return dict in the format
             {"resetMethod": "", "pendingRef": "", "linkId": "", "maskedEmail": ""}
            The contents will differ according to the chosen reset method. 'pendingRef'
            and 'linkId' will only appear of 'resetMethod' == 'enchantedlink'

        Raise:
        AuthException: raised if send reset operation fails
        """

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty"
            )

        uri = EndpointsV1.send_reset_password_path
        body: dict[str, str | bool | dict | None] = {
            "loginId": login_id,
            "redirectUrl": redirect_url,
        }
        if template_options is not None:
            body["templateOptions"] = template_options

        response = self._http.post(uri, body=body)

        return response.json()

    def update(self, login_id: str, new_password: str, refresh_token: str) -> None:
        """
        Update a password for an existing logged in user using their refresh token.

        Args:
        login_id (str): The login ID of the user whose information is being updated
        new_password (str): The new password to use
        refresh_token (str): The session's refresh token (used for verification)

        Raise:
        AuthException: raised if refresh token is invalid or update operation fails
        """

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty"
            )

        if not new_password:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "new_password cannot be empty"
            )

        if not refresh_token:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "Refresh token cannot be empty"
            )

        uri = EndpointsV1.update_password_path
        self._http.post(
            uri,
            body={"loginId": login_id, "newPassword": new_password},
            pswd=refresh_token,
        )

    def replace(
        self,
        login_id: str,
        old_password: str,
        new_password: str,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        """
        Replace a valid active password with a new one. The old_password is used to
        authenticate the user. If the user cannot be authenticated, this operation
        will fail.

        Args:
        login_id (str): The login ID of the user whose information is being updated
        old_password (str): The user's current active password
        new_password (str): The new password to use

                        Return value (dict):
        Return dict in the format
             {"jwts": [], "user": "", "firstSeen": false, "error": ""}
        Includes all the jwts tokens (session token, refresh token), token claims, and user information

        Raise:
        AuthException: raised if replace operation fails
        """

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty"
            )

        if not old_password:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "old_password cannot be empty"
            )

        if not new_password:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "new_password cannot be empty"
            )

        uri = EndpointsV1.replace_password_path
        response = self._http.post(
            uri,
            body={
                "loginId": login_id,
                "oldPassword": old_password,
                "newPassword": new_password,
            },
        )

        resp = response.json()
        jwt_response = self._auth.generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience
        )
        return jwt_response

    def get_policy(self) -> dict:
        """
        Get a subset of the password policy defined in the Descope console and enforced
        by Descope. The goal is to enable client-side validations to give users a better UX

        Return value (dict):
        Return dict in the format
             {"minLength": 8, "lowercase": true, "uppercase": true, "number": true, "nonAlphanumeric": true}
            minLength - the minimum length of a password
            lowercase - the password required at least one lowercase character
            uppercase - the password required at least one uppercase character
            number - the password required at least one number character
            nonAlphanumeric - the password required at least one non alphanumeric character

        Raise:
        AuthException: raised if get policy operation fails
        """

        response = self._http.get(uri=EndpointsV1.password_policy_path)
        return response.json()

    @staticmethod
    def _compose_signup_body(login_id: str, password: str, user: dict | None) -> dict:
        body: dict[str, str | bool | dict] = {"loginId": login_id, "password": password}
        if user is not None:
            body["user"] = user
        return body
