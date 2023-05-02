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
