# Async SDK Implementation Plan (v2)

## Decision: Separate `AsyncDescopeClient` + async subclasses

The chosen approach mirrors how Anthropic, OpenAI, and httpx structure dual-mode SDKs:
- `DescopeClient` — sync, unchanged, zero risk of regression
- `AsyncDescopeClient` — new, all `async def` methods, proper `Awaitable[T]` return types everywhere
- Shared static helpers (URL composition, body construction) inherited — not duplicated

No code generation, no build step, no `Union[T, Awaitable[T]]` anywhere.

---

## Stage 1 — `AsyncHTTPClient`

**File: `descope/async_http_client.py`**

`AsyncHTTPClient` inherits from `HTTPClient`. It gets all the shared setup logic
(`__init__`, SSL context, base_url resolution, management_key handling, verbose mode,
`_get_default_headers`, `_raise_from_response`, `_parse_retry_after`,
`_raise_rate_limit_exception`, `base_url_for_project_id`) for free.

Its `__init__` calls `super().__init__()` then creates the `httpx.AsyncClient`:

```python
class AsyncHTTPClient(HTTPClient):
    def __init__(self, project_id, base_url=None, *, timeout_seconds, secure,
                 management_key=None, verbose=False) -> None:
        super().__init__(project_id, base_url, timeout_seconds=timeout_seconds,
                         secure=secure, management_key=management_key, verbose=verbose)
        self._async_client = httpx.AsyncClient(
            verify=self.client_verify,
            timeout=self.timeout_seconds,
        )
```

Then override each transport method with `async def`:

```python
    async def get(self, uri, *, params=None, allow_redirects=True, pswd=None) -> httpx.Response:
        response = await self._async_execute_with_retry(
            lambda: self._async_client.get(
                f"{self.base_url}{uri}",
                headers=self._get_default_headers(pswd),
                params=params,
                follow_redirects=cast(bool, allow_redirects),
            )
        )
        if self.verbose:
            self._thread_local.last_response = DescopeResponse(response)
        self._raise_from_response(response)
        return response

    async def post(self, uri, *, body=None, params=None, pswd=None, base_url=None) -> httpx.Response:
        ...  # same pattern

    # put, patch, delete — same pattern

    async def _async_execute_with_retry(self, request_fn) -> httpx.Response:
        response = await request_fn()
        for delay in _RETRY_DELAYS_SECONDS:
            if response.status_code not in _RETRY_STATUS_CODES:
                break
            await response.aclose()
            await asyncio.sleep(delay)
            response = await request_fn()
        return response

    async def aclose(self) -> None:
        await self._async_client.aclose()

    async def __aenter__(self) -> "AsyncHTTPClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.aclose()
```

**Type note**: Mypy will flag `async def get(...)` as an incompatible override of `HTTPClient.get` (sync → async return type change). Add `# type: ignore[override]` on each override. This is the only concession to type purity in the entire plan, and it's contained to `AsyncHTTPClient`.

---

## Stage 2 — `Auth` stays sync

`Auth` does CPU-bound JWT validation and a one-time public key fetch (using `HTTPClient`).
None of this needs to be async — JWT crypto is not I/O. `Auth` is unchanged.

`AsyncDescopeClient` will create a regular (sync) `HTTPClient` solely to hand to `Auth`
for its internal public key fetch, then create an `AsyncHTTPClient` for all user-facing calls.
This is acceptable: the key fetch is a one-time initialization call, not per-request.

---

## Stage 3 — `AsyncAuthBase`

**File: `descope/_auth_base.py`** (add `AsyncAuthBase` alongside existing `AuthBase`)

```python
class AsyncAuthBase:
    """Base for async auth method classes."""

    def __init__(self, auth: Auth, http: AsyncHTTPClient):
        self._auth = auth          # sync Auth — used only for JWT helpers (no I/O)
        self._http = http          # AsyncHTTPClient — used for all network calls
```

`self._auth` is used only for sync operations that don't touch the network:
`Auth.extract_masked_address()`, `Auth.validate_email()`, `Auth.compose_url()`,
`self._auth.generate_jwt_response()`, `self._auth.adjust_and_verify_delivery_method()`.
All of these are pure computation — no I/O — so keeping `Auth` sync is correct.

---

## Stage 4 — Async authmethod classes

**Pattern**: Each `Foo(AuthBase)` gets a sibling `AsyncFoo(AsyncAuthBase)` **in the same file**.
`AsyncFoo` inherits none of `Foo`'s instance methods (they're sync), but it *does* call
the same `@staticmethod _compose_*` methods which live on `Foo` and are referenced directly.

```python
# In descope/authmethod/otp.py (after the existing OTP class)

class AsyncOTP(AsyncAuthBase):
    async def sign_in(
        self,
        method: DeliveryMethod,
        login_id: str,
        login_options: LoginOptions | None = None,
        refresh_token: str | None = None,
    ) -> str:
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty")
        validate_refresh_token_provided(login_options, refresh_token)
        uri = OTP._compose_signin_url(method)          # reuse sync static helper
        body = OTP._compose_signin_body(login_id, login_options)
        response = await self._http.post(uri, body=body, pswd=refresh_token)  # only change
        return Auth.extract_masked_address(response.json(), method)

    async def sign_up(self, ...) -> str: ...
    async def sign_up_or_in(self, ...) -> str: ...
    async def verify_code(self, ...) -> dict: ...
    async def update_user_email(self, ...) -> str: ...
    async def update_user_phone(self, ...) -> str: ...
```

The `@staticmethod _compose_*` methods are called as `OTP._compose_signin_url(method)` —
they don't need to be duplicated, just referenced from the sync class.

**Authmethod files to add `Async*` to**:
- `otp.py` → `AsyncOTP`
- `totp.py` → `AsyncTOTP`
- `magiclink.py` → `AsyncMagicLink`
- `enchantedlink.py` → `AsyncEnchantedLink`
- `oauth.py` → `AsyncOAuth`
- `saml.py` → `AsyncSAML`
- `sso.py` → `AsyncSSO`
- `webauthn.py` → `AsyncWebAuthn`
- `password.py` → `AsyncPassword`

Each follows the identical pattern: same method signatures, same validation, same body/URL
composition via `Foo._compose_*` statics, only `await self._http.*()` instead of `self._http.*()`.

---

## Stage 5 — Async management classes

**Pattern**: Same as authmethod — `AsyncFoo` added at the bottom of each management file.
Management classes extend `HTTPBase` (not `AuthBase`), so their async counterpart
takes only `AsyncHTTPClient`.

`AsyncHTTPBase` (add to `_http_base.py`):
```python
class AsyncHTTPBase:
    def __init__(self, http: AsyncHTTPClient):
        self._http = http
```

Each management async class:
```python
# In descope/management/user.py (after User class)

class AsyncUser(AsyncHTTPBase):
    async def create(self, login_id: str, email=None, ...) -> dict:
        # same validation as User.create
        uri = MgmtV1.user_create_path
        body = User._compose_create_body(login_id, email, ...)  # reuse static
        response = await self._http.post(uri, body=body)
        return response.json()

    async def delete(self, login_id: str) -> None:
        ...

    # all other methods follow same pattern
```

Where `User` has inline body construction (no static helper), inline it identically in `AsyncUser`.
The duplication per method is 2-3 lines of dict construction — acceptable.

**Management files to add `Async*` to**:
- `user.py` → `AsyncUser`
- `access_key.py` → `AsyncAccessKey`
- `audit.py` → `AsyncAudit`
- `authz.py` → `AsyncAuthz`
- `descoper.py` → `AsyncDescoper`
- `fga.py` → `AsyncFGA`
- `flow.py` → `AsyncFlow`
- `group.py` → `AsyncGroup`
- `jwt.py` → `AsyncJWT`
- `management_key.py` → `AsyncManagementKey`
- `outbound_application.py` → `AsyncOutboundApplication`, `AsyncOutboundApplicationByToken`
- `permission.py` → `AsyncPermission`
- `project.py` → `AsyncProject`
- `role.py` → `AsyncRole`
- `sso_application.py` → `AsyncSSOApplication`
- `sso_settings.py` → `AsyncSSOSettings`
- `tenant.py` → `AsyncTenant`

---

## Stage 6 — `AsyncMGMT`

**File: `descope/async_mgmt.py`**

Mirrors `MGMT` exactly, substituting async management classes:

```python
class AsyncMGMT:
    def __init__(self, http: AsyncHTTPClient, auth: Auth, fga_cache_url=None):
        self._http = http
        self._user = AsyncUser(http)
        self._access_key = AsyncAccessKey(http)
        self._audit = AsyncAudit(http)
        self._authz = AsyncAuthz(http, fga_cache_url=fga_cache_url)
        # ... all other async management classes

    def _ensure_management_key(self, property_name: str):
        # identical to MGMT._ensure_management_key
        if not self._http.management_key:
            raise AuthException(...)

    @property
    def user(self) -> AsyncUser:
        self._ensure_management_key("user")
        return self._user

    # ... all other properties, identical structure to MGMT
```

---

## Stage 7 — `AsyncDescopeClient`

**File: `descope/async_descope_client.py`**

```python
class AsyncDescopeClient:
    def __init__(
        self,
        project_id: str,
        public_key: dict | None = None,
        skip_verify: bool = False,
        management_key: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        jwt_validation_leeway: int = 5,
        auth_management_key: str | None = None,
        fga_cache_url: str | None = None,
        *,
        base_url: str | None = None,
        verbose: bool = False,
    ):
        project_id = project_id or os.getenv("DESCOPE_PROJECT_ID", "")
        if not project_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "...")

        if skip_verify:
            warnings.warn("⚠️  TLS verification disabled ...", UserWarning, stacklevel=2)

        # Auth uses a sync HTTPClient internally for one-time public key fetch.
        # This is the only sync client created. It is not exposed to callers.
        _auth_sync_http = HTTPClient(
            project_id=project_id,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            secure=not skip_verify,
            management_key=auth_management_key or os.getenv("DESCOPE_AUTH_MANAGEMENT_KEY"),
            verbose=verbose,
        )
        self._auth = Auth(project_id, public_key, jwt_validation_leeway,
                          http_client=_auth_sync_http)

        # All user-facing calls go through these async clients.
        self._auth_http = AsyncHTTPClient(
            project_id=project_id,
            base_url=_auth_sync_http.base_url,  # reuse resolved URL
            timeout_seconds=timeout_seconds,
            secure=not skip_verify,
            management_key=auth_management_key or os.getenv("DESCOPE_AUTH_MANAGEMENT_KEY"),
            verbose=verbose,
        )
        self._mgmt_http = AsyncHTTPClient(
            project_id=project_id,
            base_url=_auth_sync_http.base_url,
            timeout_seconds=timeout_seconds,
            secure=not skip_verify,
            management_key=management_key or os.getenv("DESCOPE_MANAGEMENT_KEY"),
            verbose=verbose,
        )

        self._otp = AsyncOTP(self._auth, self._auth_http)
        self._totp = AsyncTOTP(self._auth, self._auth_http)
        self._magiclink = AsyncMagicLink(self._auth, self._auth_http)
        self._enchantedlink = AsyncEnchantedLink(self._auth, self._auth_http)
        self._oauth = AsyncOAuth(self._auth, self._auth_http)
        self._saml = AsyncSAML(self._auth, self._auth_http)
        self._sso = AsyncSSO(self._auth, self._auth_http)
        self._webauthn = AsyncWebAuthn(self._auth, self._auth_http)
        self._password = AsyncPassword(self._auth, self._auth_http)

        self._mgmt = AsyncMGMT(self._mgmt_http, self._auth, fga_cache_url=fga_cache_url)

    # Context manager support
    async def __aenter__(self) -> "AsyncDescopeClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._auth_http.aclose()
        await self._mgmt_http.aclose()

    # Properties — identical names to DescopeClient for API parity
    @property
    def otp(self) -> AsyncOTP: return self._otp
    @property
    def totp(self) -> AsyncTOTP: return self._totp
    @property
    def magiclink(self) -> AsyncMagicLink: return self._magiclink
    @property
    def enchantedlink(self) -> AsyncEnchantedLink: return self._enchantedlink
    @property
    def oauth(self) -> AsyncOAuth: return self._oauth
    @property
    def saml(self) -> AsyncSAML: return self._saml   # deprecated
    @property
    def sso(self) -> AsyncSSO: return self._sso
    @property
    def webauthn(self) -> AsyncWebAuthn: return self._webauthn
    @property
    def password(self) -> AsyncPassword: return self._password
    @property
    def mgmt(self) -> AsyncMGMT: return self._mgmt

    # JWT validation helpers — remain sync (no I/O)
    def validate_session(self, session_token: str) -> dict:
        return self._auth.validate_session_request(session_token)

    def refresh_session(self, refresh_token: str) -> dict:
        return self._auth.refresh_session(refresh_token)

    def validate_permissions(self, jwt_response: dict, permissions: list[str]) -> bool:
        return self._auth.validate_permissions(jwt_response, permissions)

    # ... all other validate_*/get_matched_* methods from DescopeClient, unchanged

    def get_last_response(self) -> DescopeResponse | None:
        # Returns from the auth http client (most recent call)
        return self._auth_http.get_last_response()
```

---

## Stage 8 — Public API

**`descope/__init__.py`**: Add `AsyncDescopeClient` to imports and `__all__`.

```python
from descope.async_descope_client import AsyncDescopeClient
```

**Usage examples** (for README/docs, not in this plan):
```python
# As context manager (recommended):
async with AsyncDescopeClient(project_id="P...") as client:
    masked = await client.otp.sign_in(DeliveryMethod.EMAIL, "user@example.com")

# Standalone with explicit close:
client = AsyncDescopeClient(project_id="P...")
try:
    masked = await client.otp.sign_in(DeliveryMethod.EMAIL, "user@example.com")
finally:
    await client.aclose()
```

---

## File change summary

| File | Action |
|------|--------|
| `descope/async_http_client.py` | **Create** — `AsyncHTTPClient(HTTPClient)` |
| `descope/_auth_base.py` | Add `AsyncAuthBase` class |
| `descope/_http_base.py` | Add `AsyncHTTPBase` class |
| `descope/async_descope_client.py` | **Create** — `AsyncDescopeClient` |
| `descope/async_mgmt.py` | **Create** — `AsyncMGMT` |
| `descope/authmethod/otp.py` | Add `AsyncOTP` class |
| `descope/authmethod/totp.py` | Add `AsyncTOTP` class |
| `descope/authmethod/magiclink.py` | Add `AsyncMagicLink` class |
| `descope/authmethod/enchantedlink.py` | Add `AsyncEnchantedLink` class |
| `descope/authmethod/oauth.py` | Add `AsyncOAuth` class |
| `descope/authmethod/saml.py` | Add `AsyncSAML` class |
| `descope/authmethod/sso.py` | Add `AsyncSSO` class |
| `descope/authmethod/webauthn.py` | Add `AsyncWebAuthn` class |
| `descope/authmethod/password.py` | Add `AsyncPassword` class |
| `descope/management/user.py` | Add `AsyncUser` class |
| `descope/management/access_key.py` | Add `AsyncAccessKey` class |
| `descope/management/audit.py` | Add `AsyncAudit` class |
| `descope/management/authz.py` | Add `AsyncAuthz` class |
| `descope/management/descoper.py` | Add `AsyncDescoper` class |
| `descope/management/fga.py` | Add `AsyncFGA` class |
| `descope/management/flow.py` | Add `AsyncFlow` class |
| `descope/management/group.py` | Add `AsyncGroup` class |
| `descope/management/jwt.py` | Add `AsyncJWT` class |
| `descope/management/management_key.py` | Add `AsyncManagementKey` class |
| `descope/management/outbound_application.py` | Add `AsyncOutboundApplication`, `AsyncOutboundApplicationByToken` |
| `descope/management/permission.py` | Add `AsyncPermission` class |
| `descope/management/project.py` | Add `AsyncProject` class |
| `descope/management/role.py` | Add `AsyncRole` class |
| `descope/management/sso_application.py` | Add `AsyncSSOApplication` class |
| `descope/management/sso_settings.py` | Add `AsyncSSOSettings` class |
| `descope/management/tenant.py` | Add `AsyncTenant` class |
| `descope/__init__.py` | Add `AsyncDescopeClient` export |

---

## Key invariants to maintain throughout

1. **`DescopeClient` and all sync classes are unchanged in behavior** — no regressions
2. **Every `AsyncFoo` method has an identical signature to its sync counterpart**, differing only in `async def` and `await`
3. **No `Union[T, Awaitable[T]]` anywhere** — sync returns `T`, async returns `Awaitable[T]`
4. **`Auth` is never async** — it holds public keys in memory after init, JWT validation is CPU-only
5. **`AsyncHTTPClient` is the only place that touches `httpx.AsyncClient`**
6. **`AsyncDescopeClient` owns the `AsyncHTTPClient` lifecycle** — callers use context manager or explicit `aclose()`
