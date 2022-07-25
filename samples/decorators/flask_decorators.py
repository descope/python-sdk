import datetime
import os
import sys
from functools import wraps

from flask import Response, _request_ctx_stack, redirect, request

from descope.descope_client import DescopeClient

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import AuthException  # noqa: E402
from descope import (  # noqa: E402
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    DeliveryMethod,
)


def set_cookie_on_response(response, data):
    cookie_domain = data.get("cookieDomain", "")
    if cookie_domain == "":
        cookie_domain = None

    current_time = datetime.datetime.now()
    expire_time = current_time + datetime.timedelta(days=30)

    return response.set_cookie(
        key=data.get("cookieName", ""),
        value=data.get("jwt", ""),
        max_age=data.get("cookieMaxAge", int(expire_time.timestamp())),
        expires=data.get("cookieExpiration", expire_time),
        path=data.get("cookiePath", ""),
        domain=cookie_domain,
        secure=False,  # True
        httponly=True,
        samesite="None",  # "Strict", "Lax", "None"
    )


def descope_signup_otp_by_email(descope_client):
    """
    Signup new user using OTP by email
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            email = data.get("email", None)
            user = data.get("user", None)
            if not email or email == "":
                return Response("Bad Request, missing email", 400)

            try:
                descope_client.otp.sign_up(DeliveryMethod.EMAIL, email, user)
            except AuthException as e:
                return Response(f"Failed to signup, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_signin_otp_by_email(descope_client):
    """
    Signin using OTP by email
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            email = data.get("email", None)
            if not email:
                return Response("Bad Request, missing email", 400)

            try:
                descope_client.otp.sign_in(DeliveryMethod.EMAIL, email)
            except AuthException as e:
                return Response(f"Failed to signin, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_validate_auth(descope_client):
    """
    Test for valid Access Token
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            cookies = request.cookies.copy()
            session_token = cookies.get(SESSION_COOKIE_NAME, None)
            refresh_token = cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
            try:
                claims = descope_client.validate_session_request(
                    session_token, refresh_token
                )

            except AuthException:
                return Response("Access denied", 401)

            # Save the claims on the context execute the original API
            _request_ctx_stack.top.claims = claims
            response = f(*args, **kwargs)

            tokens = claims
            for _, data in tokens.items():
                set_cookie_on_response(response, data)
            return response

        return decorated

    return decorator


def descope_verify_code_by_email(descope_client):
    """
    Verify code by email decorator
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            email = data.get("email", None)
            code = data.get("code", None)
            if not code or not email:
                return Response("Unauthorized", 401)

            try:
                jwt_response = descope_client.otp.verify_code(
                    DeliveryMethod.EMAIL, email, code
                )
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            _request_ctx_stack.top.claims = jwt_response
            response = f(*args, **kwargs)

            tokens = jwt_response["jwts"]
            for _, data in tokens.items():
                set_cookie_on_response(response, data)

            return response

        return decorated

    return decorator


def descope_verify_code_by_phone(descope_client):
    """
    Verify code by email decorator
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            phone = data.get("phone", None)
            code = data.get("code", None)
            if not code or not phone:
                return Response("Unauthorized", 401)

            try:
                jwt_response = descope_client.otp.verify_code(
                    DeliveryMethod.PHONE, phone, code
                )
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            _request_ctx_stack.top.claims = jwt_response
            response = f(*args, **kwargs)

            tokens = jwt_response["jwts"]
            for _, data in tokens.items():
                set_cookie_on_response(response, data)

            return response

        return decorated

    return decorator


def descope_verify_code_by_whatsapp(descope_client):
    """
    Verify code by whatsapp decorator
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            phone = data.get("phone", None)
            code = data.get("code", None)
            if not code or not phone:
                return Response("Unauthorized", 401)

            try:
                jwt_response = descope_client.otp.verify_code(
                    DeliveryMethod.WHATSAPP, phone, code
                )
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            _request_ctx_stack.top.claims = jwt_response
            response = f(*args, **kwargs)

            tokens = jwt_response["jwts"]
            for _, data in tokens.items():
                set_cookie_on_response(response, data)

            return response

        return decorated

    return decorator


def descope_signup_magiclink_by_email(descope_client, uri):
    """
    Signup new user using magiclink via email
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            email = data.get("email", None)
            user = data.get("user", None)
            if not email or email == "":
                return Response("Bad Request, missing email", 400)

            try:
                descope_client.magiclink.sign_up(DeliveryMethod.EMAIL, email, uri, user)
            except AuthException as e:
                return Response(f"Failed to signup, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_signin_magiclink_by_email(descope_client, uri):
    """
    Signin using magiclink via email
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json(force=True)
            email = data.get("email", None)
            if not email:
                return Response("Bad Request, missing email", 400)

            try:
                descope_client.magiclink.sign_in(DeliveryMethod.EMAIL, email, uri)
            except AuthException as e:
                return Response(f"Failed to signin, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_verify_magiclink_token(descope_client):
    """
    Verify magiclink token
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            code = request.args.get("t")
            if not code:
                return Response("Unauthorized", 401)

            try:
                jwt_response = descope_client.magiclink.verify(code)
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            _request_ctx_stack.top.claims = jwt_response
            response = f(*args, **kwargs)

            tokens = jwt_response["jwts"]
            for _, data in tokens.items():
                set_cookie_on_response(response, data)
            return response

        return decorated

    return decorator


def descope_logout(descope_client):
    """
    Logout
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            cookies = request.cookies.copy()
            refresh_token = cookies.get(REFRESH_SESSION_COOKIE_NAME)
            try:
                cookies = descope_client.logout(refresh_token)
            except AuthException as e:
                return Response(f"Logout failed {e}", e.status_code)

            # Execute the original API
            response = f(*args, **kwargs)

            # Copy the new empty cookies (so session will be invalidated)
            for key, val in cookies.items():
                response.set_cookie(key, val)
            return response

        return decorated

    return decorator


def descope_oauth(descope_client: DescopeClient):
    """
    OAuth login
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                args = request.args
                provider = args.get("provider")
                redirect_url = descope_client.oauth.start(provider)
            except AuthException as e:
                return Response(f"OAuth failed {e}", e.status_code)

            # Execute the original API
            # (ignore return value as anyway we redirect)
            f(*args, **kwargs)

            return redirect(redirect_url, 302)

        return decorated

    return decorator
