import os
import sys

from flask import Flask, Response, jsonify, request
from flask_cors import cross_origin

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from decorators.flask_decorators import (  # noqa: E402; , descope_verify_code_by_email
    descope_validate_auth,
)

from descope import AuthException  # noqa: E402
from descope import AuthClient, DeliveryMethod, User  # noqa: E402

APP = Flask(__name__)

PROJECT_ID = ""
PUBLIC_KEY = None

# init the AuthClient
auth_client = AuthClient(PROJECT_ID, PUBLIC_KEY)


class Error(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@APP.errorhandler(Error)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


@APP.route("/api/signup")
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
        auth_client.sign_up_otp(DeliveryMethod.EMAIL, email, usr)
    except AuthException:
        return Response("Unauthorized", 401)

    response = "This is SignUp API handling"
    return jsonify(message=response)


@APP.route("/api/signin")
def signin():
    data = request.get_json(force=True)
    email = data.get("email", None)
    if not email:
        return Response("Unauthorized, missing email", 401)

    try:
        auth_client.sign_in_otp(DeliveryMethod.EMAIL, email)
    except AuthException:
        return Response("Unauthorized, something went wrong when sending email", 401)

    response = "This is SignIn API handling"
    return jsonify(message=response)


@APP.route("/api/verify")
# @descope_verify_code_by_email #Use this decorator or the inline code below
def verify():
    data = request.get_json(force=True)
    email = data.get("email", None)
    code = data.get("code", None)
    if not code or not email:
        return Response("Unauthorized", 401)

    try:
        cookies = auth_client.verify_code(DeliveryMethod.EMAIL, email, code)
    except AuthException:
        return Response("Unauthorized", 401)

    response = Response("Token verified", 200)
    for name, value in cookies.iteritems():
        response.set_cookie(name, value)
    return response


# This needs authentication
@APP.route("/api/private")
@cross_origin(headers=["Content-Type", "Authorization"])
@descope_validate_auth
def private():
    response = "This is a private API and you must be authenticated to see this"
    return jsonify(message=response)


# This doesn't need authentication
@APP.route("/")
def home():
    return "OK"


if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=9000)
