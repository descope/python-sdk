from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
)
from descope.exceptions import AuthException
from descope.authhelper import AuthHelper

class WebauthN():
    _auth_helper: AuthHelper

    def __init__(self, auth_helper):
        self._auth_helper = auth_helper

    @staticmethod
    def _compose_signup_body(identifier: str, user: dict) -> dict:
        body = { "externalId": identifier }
        if user is not None:
            body["user"] = user
        return body

    @staticmethod
    def _compose_sign_up_finish_body(transactionID: str, response: str) -> dict:
        return {"transactionID": transactionID,
                "response": response}

    def sign_up_start(self, identifier: str, user: dict = None) -> dict:
        """
        Docs
        """
        if identifier is None or identifier == "":
            raise AuthException(500, "Invalid argument", "Identifier cannot be empty")

        uri = EndpointsV1.signUpAuthWebauthnStart
        body = WebauthN._compose_signup_body(identifier, user)
        response = self._auth_helper.do_post(uri, body)

        resp = response.json()
        print(resp)
        return resp

    def sign_up_finish(self, transactionID: str, response: str) -> dict:
        """
        Docs
        """

        if transactionID is None or transactionID == "":
            raise AuthException(500, "Invalid argument", "TransactionID cannot be empty")

        #Which type "response" is? (I just set str..)
        if response is None or response == "":
            raise AuthException(500, "Invalid argument", "Response cannot be empty")        

        uri = EndpointsV1.signUpAuthWebauthnFinish
        body = WebauthN._compose_sign_up_finish_body(transactionID, response)
        response = self._auth_helper.do_post(uri, body) #TODO: uri should go point to another webauthn service

        resp = response.json()
        jwt_response = self._auth_helper._generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

        
    