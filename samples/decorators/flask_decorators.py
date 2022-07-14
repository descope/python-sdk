import os
import sys
from functools import wraps

from flask import Response, _request_ctx_stack, redirect, request

dir_name = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(dir_name, "../"))
from descope import AuthException  # noqa: E402
from descope import (  # noqa: E402
    REFRESH_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    DeliveryMethod,
)

def set_cookie_on_response(response, data, token):
    return response.set_cookie(
        key=data.get("cookieName", ""),
        value=token,
        max_age=data.get("cookieMaxAge", 2591999),
        expires=data.get("cookieExpiration", 1660336439),
        path=data.get("cookiePath", ""),
        #domain=data.get("cookieDomain", ""), #Setting 'domain' for a cookie on a server running locally (ex: localhost) is not supported by complying browsers. You should have something like: '127.0.0.1 localhost dev.localhost' on your hosts file and then point your server to run on 'dev.localhost' and also set 'domain' for 'dev.localhost'
        secure=True,
        httponly=True,
        samesite="None" #"Strict", "Lax", "None"
    )


def descope_signup_otp_by_email(auth_client):

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
                auth_client.sign_up_otp(DeliveryMethod.EMAIL, email, user)
            except AuthException as e:
                return Response(f"Failed to signup, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_signin_otp_by_email(auth_client):
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
                auth_client.sign_in_otp(DeliveryMethod.EMAIL, email)
            except AuthException as e:
                return Response(f"Failed to signin, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_validate_auth(auth_client):
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
                claims, tokens = auth_client.validate_session_request(
                    session_token, refresh_token
                )
                cookies[SESSION_COOKIE_NAME] = tokens[SESSION_COOKIE_NAME]
            except AuthException:
                return Response(
                    "Access denied",
                    401,
                    {"WWW-Authenticate": 'Basic realm="Login Required"'},
                )

            # Save the claims on the context execute the original API
            _request_ctx_stack.top.claims = claims
            response = f(*args, **kwargs)

            for key, val in cookies.items():
                response.set_cookie(key, val)
            return response
        return decorated
    return decorator


def descope_verify_code_by_email(auth_client):
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
                jwt_response, session_token = auth_client.verify_code(
                    DeliveryMethod.EMAIL, email, code
                )
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            _request_ctx_stack.top.claims = (jwt_response, session_token)
            response = f(*args, **kwargs)
            print(jwt_response)
            tokens = jwt_response["jwts"]
            for token, data in tokens.items():
                set_cookie_on_response(response, data, token)
            print(response.headers)

            return response
        return decorated
    return decorator


def descope_verify_code_by_phone(auth_client):
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
                claims, tokens = auth_client.verify_code(
                    DeliveryMethod.PHONE, phone, code
                )
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            _request_ctx_stack.top.claims = claims
            response = f(*args, **kwargs)

            for key, val in tokens.items():
                response.set_cookie(key, val)
                #set_cookie_on_response(..)
            return response

        return decorated

    return decorator


def descope_verify_code_by_whatsapp(auth_client):
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
                claims, tokens = auth_client.verify_code(
                    DeliveryMethod.WHATSAPP, phone, code
                )
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            _request_ctx_stack.top.claims = claims
            response = f(*args, **kwargs)

            for key, val in tokens.items():
                response.set_cookie(key, val)
            return response

        return decorated

    return decorator


def descope_signup_magiclink_by_email(auth_client, uri):
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
                auth_client.sign_up_magiclink(DeliveryMethod.EMAIL, email, uri, user)
            except AuthException as e:
                return Response(f"Failed to signup, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_signin_magiclink_by_email(auth_client, uri):
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
                auth_client.sign_in_magiclink(DeliveryMethod.EMAIL, email, uri)
            except AuthException as e:
                return Response(f"Failed to signin, err: {e}", 500)

            return f(*args, **kwargs)

        return decorated

    return decorator


def descope_verify_magiclink_token(auth_client):
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
                claims, tokens = auth_client.verify_magiclink(code)
            except AuthException:
                return Response("Unauthorized", 401)

            # Save the claims on the context execute the original API
            _request_ctx_stack.top.claims = claims
            response = f(*args, **kwargs)

            for key, val in tokens.items():
                response.set_cookie(key, val)
            return response

        return decorated

    return decorator


def descope_logout(auth_client):
    """
    Logout
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            cookies = request.cookies.copy()
            session_token = cookies.get(SESSION_COOKIE_NAME)
            refresh_token = cookies.get(REFRESH_SESSION_COOKIE_NAME)
            try:
                cookies = auth_client.logout(session_token, refresh_token)
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


def descope_oauth(auth_client):
    """
    OAuth login
    """

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                args = request.args
                provider = args.get("provider")
                redirect_url = auth_client.oauth_start(provider)
            except AuthException as e:
                return Response(f"OAuth failed {e}", e.status_code)

            # Execute the original API
            # (ignore return value as anyway we redirect)
            f(*args, **kwargs)

            return redirect(redirect_url, 302)

        return decorated

    return decorator
