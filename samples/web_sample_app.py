import os
import sys
from functools import wraps

from flask import Flask, Response, jsonify, request
from flask_cors import cross_origin

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import AuthException  # noqa: E402
from descope import (  # noqa: E402
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    AuthClient,
    DeliveryMethod,
    User,
)

APP = Flask(__name__)

PUBLIC_KEY = """{"crv": "P-384", "key_ops": ["verify"], "kty": "EC", "x": "Zd7Unk3ijm3MKXt9vbHR02Y1zX-cpXu6H1_wXRtMl3e39TqeOJ3XnJCxSfE5vjMX", "y": "Cv8AgXWpMkMFWvLGhJ_Gsb8LmapAtEurnBsFI4CAG42yUGDfkZ_xjFXPbYssJl7U", "alg": "ES384", "use": "sig", "kid": "32b3da5277b142c7e24fdf0ef09e0919"}"""
# valid cookie to be used with the above public key
# VALID_COOKIE = """S=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh; Path=/; Expires=Mon, 15 May 2023 14:52:29 GMT;"""
# invalid cookie to be used for testing Response 401 Unauthorize error
# INVALID_COOKIE = """eyJhbGciOiJFUzM4NCIsImtpZCI6IjI5OXBzbmVYOTJLM3ZwYnFQTVJDbmJaS2IyNyIsInR5cCI6IkpXVCJ9.eyJleHAiOi01Njk3NDE5NDA0LCJpc3MiOiIyOTlwc25lWDkySzN2cGJxUE1SQ25iWktiMjciLCJzdWIiOiIyOUNHZTJ5cWVLUkxvV1Y5SFhTNmtacDJvRjkifQ.zqfbAzLcdxCZHW-bw5PbmPovrcIHWAYOFLqGvPDB7vUMG33w-5CcQtdVOiYX-CW5PBudtsSfkE1C3eiiqgWj4MUyKeK6oUWm6KRpaB5T58pxVxTa9OWcEBdT8oBW0Yit"""

PROJECT_ID = "299psneX92K3vpbqPMRCnbZKb27"


# init the AuthClient
auth_client = AuthClient(PROJECT_ID, PUBLIC_KEY)


def descope_validate_auth(f):
    """
    Test for valid Access Token
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        cookies = request.cookies.copy()
        session_token = cookies.get(SESSION_COOKIE_NAME)
        refresh_token = cookies.get(REFRESH_SESSION_COOKIE_NAME)
        try:
            session_token = auth_client.validate_session_request(
                session_token, refresh_token
            )
            cookies[SESSION_COOKIE_NAME] = session_token
        except AuthException:
            return Response(
                "Access denied",
                401,
                {"WWW-Authenticate": 'Basic realm="Login Required"'},
            )

        # Execute the original API
        response = f(*args, **kwargs)

        for key, val in cookies.items():
            response.set_cookie(key, val)
        return response

    return decorated


def descope_verify_code(f):
    """
    Verify code
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        data = request.get_json(force=True)
        email = data.get("email", None)
        code = data.get("code", None)
        if not code or not email:
            return Response("Unauthorized", 401)

        try:
            cookies = auth_client.verify_code(DeliveryMethod.EMAIL, email, code)
        except AuthException:
            return Response("Unauthorized", 401)

        # Execute the original API
        response = f(*args, **kwargs)

        for key, val in cookies.items():
            response.set_cookie(key, val)
        return response

    return decorated


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
        return Response("Unauthorized", 401)

    try:
        auth_client.sign_in_otp(DeliveryMethod.EMAIL, email)
    except AuthException:
        return Response("Unauthorized", 401)

    response = "This is SignIn API handling"
    return jsonify(message=response)


@APP.route("/api/verify")
# @descope_verify_code #Use this decorator or the inline code below
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

    response = Response("", 200)
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
    return "Hello"


if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=9000)
