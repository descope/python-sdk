from descope.auth import Auth
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException
from descope.management.common import MgmtV1


class JWT:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def updateJWT(self, token: str, customClaims: dict) -> str:
        """
        Given a valid JWT, update it with custom claims, and update its authz claims as well

        Args:
        token (str): valid jwt.
        customClaims (dict): Custom claims to add to JWT, system claims will be filtered out

        Return value (str): the newly updated JWT

        Raise:
        AuthException: raised if update failed
        """
        if not token:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "jwt cannot be empty")
        response = self._auth.do_post(
            MgmtV1.updateJwt,
            JWT._compose_update_jwt_body(token, customClaims),
            pswd=self._auth.management_key,
        )
        return response.json().get("jwt", "")

    @staticmethod
    def _compose_update_jwt_body(token: str, customClaims: dict) -> dict:
        return {"jwt": token, "customClaims": customClaims}
