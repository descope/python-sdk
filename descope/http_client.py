from __future__ import annotations

import os
import platform
from http import HTTPStatus
from typing import Optional, Union, cast

try:
    from importlib.metadata import version
except ImportError:  # pragma: no cover
    from pkg_resources import get_distribution

import requests

from descope.common import (
    DEFAULT_BASE_URL,
    DEFAULT_DOMAIN,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_URL_PREFIX,
)
from descope.exceptions import (
    API_RATE_LIMIT_RETRY_AFTER_HEADER,
    ERROR_TYPE_API_RATE_LIMIT,
    ERROR_TYPE_INVALID_ARGUMENT,
    ERROR_TYPE_SERVER_ERROR,
    AuthException,
    RateLimitException,
)


def sdk_version():
    try:
        return version("descope")  # type: ignore
    except NameError:  # pragma: no cover
        return get_distribution("descope").version  # type: ignore


_default_headers = {
    "Content-Type": "application/json",
    "x-descope-sdk-name": "python",
    "x-descope-sdk-python-version": platform.python_version(),
    "x-descope-sdk-version": sdk_version(),
}


class HTTPClient:
    def __init__(
        self,
        project_id: str,
        base_url: Optional[str] = None,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        secure: bool = True,
        management_key: Optional[str] = None,
    ) -> None:
        if not project_id:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                (
                    "Project ID is required to initialize HTTP client"
                    "Set environment variable DESCOPE_PROJECT_ID or pass your Project ID to the init function."
                ),
            )

        # Prefer explicitly provided base_url, then env var, then computed default
        env_base = os.getenv("DESCOPE_BASE_URI")
        self.base_url = base_url or env_base or self.base_url_for_project_id(project_id)

        self.project_id = project_id
        self.timeout_seconds = timeout_seconds
        self.secure = secure
        self.management_key = management_key

    # ------------- public API -------------
    def get(
        self,
        uri: str,
        *,
        params=None,
        allow_redirects: Optional[bool] = True,
        pswd: Optional[str] = None,
    ) -> requests.Response:
        response = requests.get(
            f"{self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            params=params,
            allow_redirects=cast(bool, allow_redirects),
            verify=self.secure,
            timeout=self.timeout_seconds,
        )
        self._raise_from_response(response)
        return response

    def post(
        self,
        uri: str,
        *,
        body: Optional[Union[dict, list[dict], list[str]]] = None,
        params=None,
        pswd: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> requests.Response:
        response = requests.post(
            f"{base_url or self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            json=body,
            allow_redirects=False,
            verify=self.secure,
            params=params,
            timeout=self.timeout_seconds,
        )
        self._raise_from_response(response)
        return response

    def patch(
        self,
        uri: str,
        *,
        body: Optional[Union[dict, list[dict], list[str]]],
        params=None,
        pswd: Optional[str] = None,
    ) -> requests.Response:
        response = requests.patch(
            f"{self.base_url}{uri}",
            headers=self._get_default_headers(pswd),
            json=body,
            allow_redirects=False,
            verify=self.secure,
            params=params,
            timeout=self.timeout_seconds,
        )
        self._raise_from_response(response)
        return response

    def delete(
        self,
        uri: str,
        *,
        params=None,
        pswd: Optional[str] = None,
    ) -> requests.Response:
        response = requests.delete(
            f"{self.base_url}{uri}",
            params=params,
            headers=self._get_default_headers(pswd),
            allow_redirects=False,
            verify=self.secure,
            timeout=self.timeout_seconds,
        )
        self._raise_from_response(response)
        return response

    def get_default_headers(self, pswd: Optional[str] = None) -> dict:
        return self._get_default_headers(pswd)

    # ------------- helpers -------------
    @staticmethod
    def base_url_for_project_id(project_id: str) -> str:
        if len(project_id) >= 32:
            region = project_id[1:5]
            return ".".join([DEFAULT_URL_PREFIX, region, DEFAULT_DOMAIN])
        return DEFAULT_BASE_URL

    def _parse_retry_after(self, headers) -> int:
        try:
            return int(headers.get(API_RATE_LIMIT_RETRY_AFTER_HEADER, 0))
        except (ValueError, TypeError):
            return 0

    def _raise_rate_limit_exception(self, response):
        try:
            resp = response.json()
            raise RateLimitException(
                resp.get("errorCode", HTTPStatus.TOO_MANY_REQUESTS),
                ERROR_TYPE_API_RATE_LIMIT,
                resp.get("errorDescription", ""),
                resp.get("errorMessage", ""),
                rate_limit_parameters={
                    API_RATE_LIMIT_RETRY_AFTER_HEADER: self._parse_retry_after(
                        response.headers
                    )
                },
            )
        except RateLimitException:
            raise
        except Exception:
            raise RateLimitException(
                status_code=HTTPStatus.TOO_MANY_REQUESTS,
                error_type=ERROR_TYPE_API_RATE_LIMIT,
                error_message=ERROR_TYPE_API_RATE_LIMIT,
                error_description=ERROR_TYPE_API_RATE_LIMIT,
            )

    def _raise_from_response(self, response):
        if response.ok:
            return
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            self._raise_rate_limit_exception(response)
        raise AuthException(
            response.status_code,
            ERROR_TYPE_SERVER_ERROR,
            response.text,
        )

    def _get_default_headers(self, pswd: Optional[str] = None):
        headers = _default_headers.copy()
        headers["x-descope-project-id"] = self.project_id
        bearer = self.project_id
        if pswd:
            bearer = f"{self.project_id}:{pswd}"
        if self.management_key:
            bearer = f"{bearer}:{self.management_key}"
        headers["Authorization"] = f"Bearer {bearer}"
        return headers
