from descope._auth_base import AuthBase
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.management.common import MgmtV1


class JWT(AuthBase):
    def update_jwt(self, jwt: str, custom_claims: dict) -> str:
        """
        Given a valid JWT, update it with custom claims, and update its authz claims as well

        Args:
        token (str): valid jwt.
        custom_claims (dict): Custom claims to add to JWT, system claims will be filtered out

        Return value (str): the newly updated JWT

        Raise:
        AuthException: raised if update failed
        """
        if not jwt:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "jwt cannot be empty")
        response = self._auth.do_post(
            MgmtV1.update_jwt_path,
            {"jwt": jwt, "customClaims": custom_claims},
            pswd=self._auth.management_key,
        )
        return response.json().get("jwt", "")

    def impersonate(
        self, impersonator_id: str, login_id: str, validate_consent: bool
    ) -> str:
        """
        Impersonate to another user

        Args:
        impersonator_id (str): login id / user id of impersonator, must have "impersonation" permission.
        login_id (str): login id of the user whom to which to impersonate to.
        validate_consent (bool): Indicate whether to allow impersonation in any case or only if a consent to this operation was granted.

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
        response = self._auth.do_post(
            MgmtV1.impersonate_path,
            {
                "loginId": login_id,
                "impersonatorId": impersonator_id,
                "validateConsent": validate_consent,
            },
            pswd=self._auth.management_key,
        )
        return response.json().get("jwt", "")
