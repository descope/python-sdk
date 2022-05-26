import os
import sys
from functools import wraps

from flask import Response, request

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

# init the AuthClient
auth_client = AuthClient("PROJECT_ID", None)


def descope_signup_otp_by_email(f):
    """
    Signup new user by using OTP over email
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        data = request.get_json(force=True)
        email = data.get("email", None)
        user = data.get("user", None)
        if not email or not user:
            return Response("Bad Request, missing user or email", 400)

        try:
            usr = User(
                user.get("username", "dummy"),
                user.get("name", ""),
                user.get("phone", ""),
                user.get("email", ""),
            )
            auth_client.sign_up_otp(DeliveryMethod.EMAIL, email, usr)
        except AuthException as e:
            return Response(f"Failed to signup, err: {e}", 500)

        return f(*args, **kwargs)

    return decorated


def descope_signin_otp_by_email(f):
    """
    Signin by using OTP over email
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        data = request.get_json(force=True)
        email = data.get("email", None)
        if not email:
            return Response("Bad Request, missing email", 400)

        try:
            auth_client.sign_in_otp(DeliveryMethod.EMAIL, email)
        except AuthException as e:
            return Response(f"Failed to signin, err: {e}", 500)

        return f(*args, **kwargs)

    return decorated


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


def descope_verify_code_by_email(f):
    """
    Verify code by email decorator
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


def descope_verify_code_by_phone(f):
    """
    Verify code by email decorator
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        data = request.get_json(force=True)
        phone = data.get("phone", None)
        code = data.get("code", None)
        if not code or not phone:
            return Response("Unauthorized", 401)

        try:
            cookies = auth_client.verify_code(DeliveryMethod.PHONE, phone, code)
        except AuthException:
            return Response("Unauthorized", 401)

        # Execute the original API
        response = f(*args, **kwargs)

        for key, val in cookies.items():
            response.set_cookie(key, val)
        return response

    return decorated


def descope_verify_code_by_whatsapp(f):
    """
    Verify code by whatsapp decorator
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        data = request.get_json(force=True)
        phone = data.get("phone", None)
        code = data.get("code", None)
        if not code or not phone:
            return Response("Unauthorized", 401)

        try:
            cookies = auth_client.verify_code(DeliveryMethod.WHATSAPP, phone, code)
        except AuthException:
            return Response("Unauthorized", 401)

        # Execute the original API
        response = f(*args, **kwargs)

        for key, val in cookies.items():
            response.set_cookie(key, val)
        return response

    return decorated
