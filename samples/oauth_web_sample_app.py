import os
import sys

from flask import Flask, jsonify

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from decorators.flask_decorators import (  # noqa: E402;
    descope_logout,
    descope_oauth,
    descope_validate_auth,
)

from descope import AuthClient  # noqa: E402

APP = Flask(__name__)

PROJECT_ID = ""

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


@APP.route("/api/oauth", methods=["GET"])
@descope_oauth(auth_client)
def oauth(*args, **kwargs):
    pass


# This doesn't need authentication
@APP.route("/")
def home():
    return "OK"


if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=9000)
