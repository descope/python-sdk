import json
import os
import sys

from flask import Flask, Response, _request_ctx_stack, jsonify, request

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from decorators.flask_decorators import (  # noqa: E402;
    descope_logout,
    descope_validate_auth,
    descope_verify_code_by_email,
)

from descope import AuthException  # noqa: E402
from descope import DeliveryMethod, DescopeClient  # noqa: E402

APP = Flask(__name__)

PROJECT_ID = ""

# init the DescopeClient
descope_client = DescopeClient(PROJECT_ID, base_url="https://localhost:8443")


class Error(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@APP.errorhandler(Error)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


@APP.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)
    email = data.get("email", None)
    name = data.get("name", None)
    if not email:
        return Response("Unauthorized", 401)

    try:
        user = {"name": name, "phone": "", "email": email}
        descope_client.otp.sign_up(DeliveryMethod.EMAIL, email, user)
    except AuthException:
        return Response("Unauthorized", 401)

    response = "This is SignUp API handling"
    return jsonify(message=response)


@APP.route("/api/signin", methods=["POST"])
def signin():
    data = request.get_json(force=True)
    email = data.get("email", None)
    if not email:
        return Response("Unauthorized, missing email", 401)

    try:
        descope_client.otp.sign_in(DeliveryMethod.EMAIL, email)
    except AuthException:
        return Response("Unauthorized, something went wrong when sending email", 401)

    response = "This is SignIn API handling"
    return jsonify(message=response)


@APP.route("/api/signuporin", methods=["POST"])
def signuporin():
    data = request.get_json(force=True)
    email = data.get("email", None)
    if not email:
        return Response("Unauthorized, missing email", 401)

    try:
        descope_client.otp.sign_up_or_in(DeliveryMethod.EMAIL, email)
    except AuthException:
        return Response("Unauthorized, something went wrong when sending email", 401)

    response = "This is SignUpOrIn API handling"
    return jsonify(message=response)


@APP.route("/api/verify", methods=["POST"])
def verify():
    data = request.get_json(force=True)
    email = data.get("email", None)
    code = data.get("code", None)
    if not code or not email:
        return Response("Unauthorized", 401)

    try:
        jwt_response = descope_client.otp.verify_code(DeliveryMethod.EMAIL, email, code)
    except AuthException:
        return Response("Unauthorized", 401)

    response = Response(json.dumps(jwt_response), 200)
    return response


@APP.route("/api/verify_by_decorator", methods=["POST"])
@descope_verify_code_by_email(descope_client)
def verify_by_decorator(*args, **kwargs):
    claims = _request_ctx_stack.top.claims

    response = f"This is a code verification API, claims are: {claims}"
    return jsonify(message=response)


# This needs authentication
@APP.route("/api/private", methods=["POST"])
@descope_validate_auth(descope_client)
def private():
    response = "This is a private API and you must be authenticated to see this"
    return jsonify(message=response)


@APP.route("/api/logout")
@descope_logout(descope_client)
def logout():
    response = "Logged out"
    return jsonify(message=response)


# This doesn't need authentication
@APP.route("/")
def home():
    return "OK"


if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=9000)
