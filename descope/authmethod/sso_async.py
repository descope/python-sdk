from __future__ import annotations

from typing import Optional

from descope._authmethod_base import AsyncAuthMethodBase
from descope.authmethod._sso_base import SSOBase
from descope.common import (
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)


class SSOAsync(SSOBase, AsyncAuthMethodBase):
    """Async SSO auth-method. All network calls are coroutines; validation is sync (no I/O)."""

    async def start(
        self,
        tenant: str,
        return_url: Optional[str] = None,
        login_options: Optional[LoginOptions] = None,
        refresh_token: Optional[str] = None,
        prompt: Optional[str] = None,
        sso_id: Optional[str] = None,
        login_hint: Optional[str] = None,
        force_authn: Optional[bool] = None,
    ) -> dict:
        """Start an SSO flow; returns the redirect URL to send the user to."""
        self._validate_tenant(tenant)

        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.auth_sso_start_path
        params = self._compose_start_params(
            tenant,
            return_url if return_url else "",
            prompt if prompt else "",
            sso_id if sso_id else "",
            login_hint if login_hint else "",
            force_authn,
        )
        response = await self._http.post(
            uri,
            body=login_options.__dict__ if login_options else {},
            params=params,
            pswd=refresh_token,
        )
        return response.json()

    async def exchange_token(self, code: str) -> dict:
        """Exchange an SSO code for session JWTs."""
        return await self._auth.exchange_token(EndpointsV1.sso_exchange_token_path, code)
