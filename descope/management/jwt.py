from typing import Optional

from descope._http_base import HTTPBase
from descope.auth import Auth
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.jwt_common import generate_jwt_response
from descope.management.common import (
    MgmtLoginOptions,
    MgmtSignUpOptions,
    MgmtUserRequest,
    MgmtV1,
    is_jwt_required,
)


class JWT(HTTPBase):
    _auth: Auth

    def __init__(self, http_client, auth: Auth):
        super().__init__(http_client)
        self._auth = auth

    def update_jwt(
        self, jwt: str, custom_claims: dict, refresh_duration: int = 0
    ) -> str:
        """
        Given a valid JWT, update it with custom claims, and update its authz claims as well

        Args:
        token (str): valid jwt.
        custom_claims (dict): Custom claims to add to JWT, system claims will be filtered out
        refresh_duration (int): duration in seconds for which the new JWT will be valid

        Return value (str): the newly updated JWT

        Raise:
        AuthException: raised if update failed
        """
        if not jwt:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "jwt cannot be empty")
        response = self._http.post(
            MgmtV1.update_jwt_path,
            body={
                "jwt": jwt,
                "customClaims": custom_claims,
                "refreshDuration": refresh_duration,
            },
            params=None,
        )
        return response.json().get("jwt", "")

    def impersonate(
        self,
        impersonator_id: str,
        login_id: str,
        validate_consent: bool,
        custom_claims: Optional[dict] = None,
        tenant_id: Optional[str] = None,
        refresh_duration: Optional[int] = None,
    ) -> str:
        """
        Impersonate to another user

        Args:
        impersonator_id (str): login id / user id of impersonator, must have "impersonation" permission.
        login_id (str): login id of the user whom to which to impersonate to.
        validate_consent (bool): Indicate whether to allow impersonation in any case or only if a consent to this operation was granted.
        customClaims dict: Custom claims to add to JWT
        tenant_id (str): tenant id to set on DCT claim.
        refresh_duration (int): duration in seconds for which the new JWT will be valid

        Return value (str): A JWT of the impersonated user

        Raise:
        AuthException: raised if update failed
        """
        if not impersonator_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "impersonator_id cannot be empty"
            )
        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty"
            )
        response = self._http.post(
            MgmtV1.impersonate_path,
            body={
                "loginId": login_id,
                "impersonatorId": impersonator_id,
                "validateConsent": validate_consent,
                "customClaims": custom_claims,
                "selectedTenant": tenant_id,
                "refreshDuration": refresh_duration,
            },
            params=None,
        )
        return response.json().get("jwt", "")

    def stop_impersonation(
        self,
        jwt: str,
        custom_claims: Optional[dict] = None,
        tenant_id: Optional[str] = None,
        refresh_duration: Optional[int] = None,
    ) -> str:
        """
        Stop impersonation and return to the original user
        Args:
        jwt (str): The impersonation jwt to stop.
        customClaims dict: Custom claims to add to JWT
        tenant_id (str): tenant id to set on DCT claim.
        refresh_duration (int): duration in seconds for which the new JWT will be valid

        Return value (str): A JWT of the actor

        Raise:
        AuthException: raised if update failed
        """
        if not jwt or jwt == "":
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "jwt cannot be empty")

        response = self._http.post(
            MgmtV1.stop_impersonation_path,
            body={
                "jwt": jwt,
                "customClaims": custom_claims,
                "selectedTenant": tenant_id,
                "refreshDuration": refresh_duration,
            },
            params=None,
        )
        return response.json().get("jwt", "")

    def sign_in(
        self, login_id: str, login_options: Optional[MgmtLoginOptions] = None
    ) -> dict:
        """
        Generate a JWT for a user, simulating a signin request.

        Args:
        login_id (str): login id of the user.
        login_options (MgmtLoginOptions): options for the login request.
        """

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty"
            )

        if login_options is None:
            login_options = MgmtLoginOptions()

        if is_jwt_required(login_options) and not login_options.jwt:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "JWT is required")

        response = self._http.post(
            MgmtV1.mgmt_sign_in_path,
            body={
                "loginId": login_id,
                "stepup": login_options.stepup,
                "mfa": login_options.mfa,
                "revokeOtherSessions": login_options.revoke_other_sessions,
                "customClaims": login_options.custom_claims,
                "jwt": login_options.jwt,
                "refreshDuration": login_options.refresh_duration,
            },
            params=None,
        )
        resp = response.json()
        jwt_response = generate_jwt_response(
            resp, None, None, self._auth.validate_token
        )
        return jwt_response

    def sign_up(
        self,
        login_id: str,
        user: Optional[MgmtUserRequest] = None,
        signup_options: Optional[MgmtSignUpOptions] = None,
    ) -> dict:
        """
        Generate a JWT for a user, simulating a signup request.

        Args:
        login_id (str): login id of the user.
        user (MgmtUserRequest): user details.
        signup_options (MgmtSignUpOptions): signup options.
        """

        return self._sign_up_internal(
            login_id, MgmtV1.mgmt_sign_up_path, user, signup_options
        )

    def sign_up_or_in(
        self,
        login_id: str,
        user: Optional[MgmtUserRequest] = None,
        signup_options: Optional[MgmtSignUpOptions] = None,
    ) -> dict:
        """
        Generate a JWT for a user, simulating a signup or in request.

        Args:
        login_id (str): login id of the user.
        user (MgmtUserRequest): user details.
        signup_options (MgmtSignUpOptions): signup options.
        """
        return self._sign_up_internal(
            login_id, MgmtV1.mgmt_sign_up_or_in_path, user, signup_options
        )

    def _sign_up_internal(
        self,
        login_id: str,
        endpoint: str,
        user: Optional[MgmtUserRequest] = None,
        signup_options: Optional[MgmtSignUpOptions] = None,
    ) -> dict:
        if user is None:
            user = MgmtUserRequest()

        if not login_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty"
            )

        if signup_options is None:
            signup_options = MgmtSignUpOptions()

        response = self._http.post(
            endpoint,
            body={
                "loginId": login_id,
                "user": user.to_dict(),
                "emailVerified": user.email_verified,
                "phoneVerified": user.phone_verified,
                "ssoAppId": user.sso_app_id,
                "customClaims": signup_options.custom_claims,
                "refreshDuration": signup_options.refresh_duration,
            },
            params=None,
        )
        resp = response.json()
        jwt_response = generate_jwt_response(
            resp, None, None, self._auth.validate_token
        )
        return jwt_response

    def anonymous(
        self,
        custom_claims: Optional[dict] = None,
        tenant_id: Optional[str] = None,
        refresh_duration: Optional[int] = None,
    ) -> dict:
        """
        Generate a JWT for an anonymous user.

        Args:
        custom_claims dict: Custom claims to add to JWT
        tenant_id (str): tenant id to set on DCT claim.
        """

        response = self._http.post(
            MgmtV1.anonymous_path,
            body={
                "customClaims": custom_claims,
                "selectedTenant": tenant_id,
                "refreshDuration": refresh_duration,
            },
            params=None,
        )
        resp = response.json()
        jwt_response = generate_jwt_response(
            resp, None, None, self._auth.validate_token
        )
        del jwt_response["firstSeen"]
        del jwt_response["user"]
        return jwt_response
