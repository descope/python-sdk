import os
import sys

from flask import Flask, Response, _request_ctx_stack, jsonify, request

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from decorators.flask_decorators import (  # noqa: E402;
    descope_logout,
    descope_validate_auth,
    descope_verify_magiclink_token,
)

from descope import AuthException  # noqa: E402
from descope import AuthClient, DeliveryMethod, User  # noqa: E402

APP = Flask(__name__)

PROJECT_ID = ""
URI = "http://127.0.0.1:9000/api/verify_by_decorator"

# init the AuthClient
auth_client = AuthClient(PROJECT_ID)


class Error(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@APP.errorhandler(Error)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


@APP.route("/api/signup", methods = ['POST'])
def signup():
    data = request.get_json(force=True)
    email = data.get("email", None)
    user = data.get("user", None)
    if not email or not user:
        return Response("Unauthorized", 401)

    try:
        usr = User(
            user.get("username", "dummy"),
            user.get("name", ""),
            user.get("phone", ""),
            user.get("email", ""),
        )
        auth_client.sign_up_magiclink(DeliveryMethod.EMAIL, email,URI, usr)
    except AuthException:
        return Response("Unauthorized", 401)

    response = "This is SignUp API handling"
    return jsonify(message=response)


@APP.route("/api/signin", methods = ['POST'])
def signin():
    data = request.get_json(force=True)
    email = data.get("email", None)
    if not email:
        return Response("Unauthorized, missing email", 401)

    try:
        auth_client.sign_in_magiclink(DeliveryMethod.EMAIL, email, URI)
    except AuthException:
        return Response("Unauthorized, something went wrong when sending email", 401)

    response = "This is SignIn API handling"
    return jsonify(message=response)


@APP.route("/api/verify", methods = ['POST'])
def verify():
    data = request.get_json(force=True)
    code = data.get("code", None)
    if not code:
        return Response("Unauthorized", 401)

    try:
        _, tokens = auth_client.verify_magiclink(DeliveryMethod.EMAIL, code)
    except AuthException:
        return Response("Unauthorized", 401)

    response = Response("Token verified", 200)
    for name, value in tokens.iteritems():
        response.set_cookie(name, value)

    return response


@APP.route("/api/verify_by_decorator", methods = ['GET'])
@descope_verify_magiclink_token(auth_client)
def verify_by_decorator(*args, **kwargs):
    claims = _request_ctx_stack.top.claims
    response = f"This is a code verification API, claims are: {claims}"
    return jsonify(message=response)


# This needs authentication
@APP.route("/api/private")
@descope_validate_auth(auth_client)
def private():
    response = "This is a private API and you must be authenticated to see this"
    return jsonify(message=response)


@APP.route("/api/logout")
@descope_logout(auth_client)
def logout():
    response = "Logged out"
    return jsonify(message=response)


# This doesn't need authentication
@APP.route("/")
def home():
    return "OK"


if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=9000)
