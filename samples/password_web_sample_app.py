import datetime
import os
import sys

from flask import Flask, Response, jsonify, request

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import COOKIE_DATA_NAME  # noqa: E402
from descope import (
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    SESSION_TOKEN_NAME,
    AuthException,
    DescopeClient,
)

APP = Flask(__name__)

PROJECT_ID = ""

# init the DescopeClient
descope_client = DescopeClient(PROJECT_ID, skip_verify=True)


def set_cookie_on_response(response: Response, token: dict, cookie_data: dict):
    cookie_domain = cookie_data.get("domain", "")
    if cookie_domain == "":
        cookie_domain = None

    current_time = datetime.datetime.now()
    expire_time = current_time + datetime.timedelta(days=30)

    return response.set_cookie(
        key=token.get("drn", ""),
        value=token.get("jwt", ""),
        max_age=cookie_data.get("maxAge", int(expire_time.timestamp())),
        expires=cookie_data.get("exp", expire_time),
        path=cookie_data.get("path", "/"),
        domain=cookie_domain,
        secure=False,  # True
        httponly=True,
        samesite="Strict",  # "Strict", "Lax", "None"
    )


class Error(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@APP.errorhandler(Error)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


@APP.route("/password/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)
    email = data.get("email", None)
    password = data.get("password", None)
    name = data.get("name", None)
    if not email or not password:
        return Response("Unauthorized", 401)

    try:
        user = {"name": name, "phone": "", "email": email}
        descope_client.password.sign_up(email, password, user)
    except AuthException as ex:
        return Response(f"Unauthorized, failed to sign up with password {ex}", 401)

    return Response("This is SignUp API handling", 200)


@APP.route("/password/signin", methods=["POST"])
def signin():
    data = request.get_json(force=True)
    email = data.get("email", None)
    password = data.get("password", None)
    if not email or not password:
        return Response("Unauthorized, email and password are required", 401)

    try:
        descope_client.password.sign_in(email, password)
    except AuthException as ex:
        return Response(
            f"Unauthorized, failed to authenticated with password {ex}", 401
        )

    return Response("This is SignIn API handling", 200)


# This needs authentication
@APP.route("/api/private", methods=["POST"])
def private():
    cookies = request.cookies.copy()
    session_token = cookies.get(SESSION_COOKIE_NAME, None)
    refresh_token = cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
    try:
        jwt_response = descope_client.validate_and_refresh_session(
            session_token, refresh_token
        )
    except AuthException:
        return Response("Access denied", 401)

    response = Response(
        "This is a private API and you must be authenticated to see this", 200
    )

    if jwt_response.get(COOKIE_DATA_NAME, None):
        set_cookie_on_response(
            response, jwt_response[SESSION_TOKEN_NAME], jwt_response[COOKIE_DATA_NAME]
        )

    return response


@APP.route("/api/logout")
def logout():
    cookies = request.cookies.copy()
    refresh_token = cookies.get(REFRESH_SESSION_COOKIE_NAME)
    try:
        descope_client.logout(refresh_token)
    except AuthException as e:
        return Response(f"Logout failed {e}", e.status_code)

    response = Response("This is Logout API handling", 200)
    response.delete_cookie(SESSION_COOKIE_NAME)
    response.delete_cookie(REFRESH_SESSION_COOKIE_NAME)
    return response


# This doesn't need authentication
@APP.route("/")
def home():
    return "OK"


if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=9000)
