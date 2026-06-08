# Test Refactoring Plan (v2) — Unified Sync/Async Testing

## Goal

Run 90% of existing tests against both `DescopeClient` (sync) and `AsyncDescopeClient`
(async) with zero duplication of test logic. The remaining 10% covers mode-specific
concerns: client initialization, HTTP transport mechanics, and lifecycle (aclose, context manager).
The 98% coverage requirement must be maintained throughout.

---

## Core problem & solution

### The fundamental challenge

You cannot `await` inside a sync function, so a test body written for a sync client
can't directly call an async client. Two building blocks solve this completely:

**1. `invoke()` — run sync or async calls uniformly from `async def` tests**

```python
async def invoke(self, maybe_coro):
    if asyncio.iscoroutine(maybe_coro):
        return await maybe_coro
    return maybe_coro
```

- Sync client: `client.otp.sign_in(...)` executes immediately, returns a value. `invoke(value)` wraps and returns it.
- Async client: `client.otp.sign_in(...)` returns an unawaited coroutine. `invoke(coro)` awaits it.

For exception tests: sync raises during argument evaluation (before `invoke` is called);
async raises when the coroutine runs inside `invoke`. Both are caught by the surrounding
`pytest.raises` context manager. No special casing needed.

**2. `UnifiedClient` — abstracts sync/async construction, client access, and mock setup**

Wraps either `DescopeClient` or `AsyncDescopeClient`, providing a uniform interface
to the test body so tests never branch on mode.

### Test depth trade-off

Current tests mock at `httpx.post` (module level) and assert on the full HTTP call
(URL, headers, JSON body). This pattern tests two things at once:
1. The auth method builds the right URI path and request body
2. `HTTPClient.post` correctly assembles the final `httpx.post` call

Unifying these two layers across sync and async is possible but requires different
`assert_called_with` signatures (sync includes `verify=SSLMatcher(), timeout=...`;
async doesn't, since those are on the client level).

**Decision**: Unified tests verify behavioral correctness (right return value, right
exceptions). Exact HTTP request construction (URL, headers, JSON body) is verified by
dedicated `test_http_client.py` and `test_async_http_client.py` tests, which is the
correct place for that concern anyway.

---

## Technology: `pytest-asyncio` in auto mode

Add `pytest-asyncio` to dev dependencies:

```toml
# pyproject.toml
[project.optional-dependencies]
dev = [
    ...
    "pytest-asyncio>=0.23",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"      # every async def test_* runs in asyncio automatically
```

With `asyncio_mode = "auto"`:
- All `async def test_*` methods run in an event loop automatically — no decorator needed.
- Regular `def test_*` methods continue to work unchanged.
- No change to existing non-async tests.

---

## The `UnifiedClient` wrapper

**File: `tests/conftest.py`**

`UnifiedClient` wraps either client variant and provides a consistent interface.
The mock abstraction is its most important role:

```python
# tests/conftest.py

import asyncio
import os
import platform
from contextlib import contextmanager
from importlib.metadata import version
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from descope.async_descope_client import AsyncDescopeClient
from descope.descope_client import DescopeClient

# --- Constants reused across all test files ---

DUMMY_PROJECT_ID = "P2CtzUhdqpIF2ys9gg7ms06UvtC4Pdummy"  # 32-char valid format
DUMMY_MGMT_KEY = "key"
DEFAULT_BASE_URL = "http://127.0.0.1"

PUBLIC_KEY_DICT = {
    "alg": "ES384",
    "crv": "P-384",
    "kid": "P2CtzUhdqpIF2ys9gg7ms06UvtC4",
    "kty": "EC",
    "use": "sig",
    "x": "pX1l7nT2turcK5_Cdzos8SKIhpLh1Wy9jmKAVyMFiOCURoj-WQX1J0OUQqMsQO0s",
    "y": "B0_nWAv2pmG_PzoH3-bSYZZzLNKUA0RoE2SH7DaS0KV4rtfWZhYd0MEr0xfdGKx0",
}

default_headers = {
    "Content-Type": "application/json",
    "x-descope-sdk-name": "python",
    "x-descope-sdk-python-version": platform.python_version(),
    "x-descope-sdk-version": version("descope"),
}


# --- Response factory ---

def make_response(json_data=None, *, status=200, cookies=None):
    """Build a mock httpx.Response for use as a mock return value."""
    mock = MagicMock()
    mock.is_success = status < 400
    mock.status_code = status
    mock.json.return_value = json_data or {}
    mock_cookies = MagicMock()
    mock_cookies.get = MagicMock(return_value=None)
    if cookies:
        mock_cookies.get = MagicMock(side_effect=lambda k, d=None: cookies.get(k, d))
    mock.cookies = mock_cookies
    mock.headers = {}
    mock.text = str(json_data or "")
    return mock


# --- Unified client wrapper ---

class UnifiedClient:
    """
    Wraps DescopeClient or AsyncDescopeClient with a uniform interface for tests.

    Test bodies call self.invoke(...) and self.mock_post(...) without knowing which
    mode they're running in. The wrapper translates to the right mock target and
    call pattern for each mode.
    """

    def __init__(self, mode: str, raw):
        self.mode = mode          # "sync" | "async"
        self._raw = raw

    def __getattr__(self, name):
        return getattr(self._raw, name)

    # --- Execution ---

    async def invoke(self, maybe_coro):
        """Uniformly execute a sync return value or an async coroutine."""
        if asyncio.iscoroutine(maybe_coro):
            return await maybe_coro
        return maybe_coro

    # --- Mock context managers ---
    # Each yields the mock object so tests can optionally call assert_called_once/etc.

    @contextmanager
    def mock_post(self, response):
        """Mock the auth HTTP client's POST method."""
        with self._patch_ctx("post", response, "auth") as mock:
            yield mock

    @contextmanager
    def mock_get(self, response):
        """Mock the auth HTTP client's GET method."""
        with self._patch_ctx("get", response, "auth") as mock:
            yield mock

    @contextmanager
    def mock_put(self, response):
        with self._patch_ctx("put", response, "auth") as mock:
            yield mock

    @contextmanager
    def mock_delete(self, response):
        with self._patch_ctx("delete", response, "auth") as mock:
            yield mock

    @contextmanager
    def mock_mgmt_post(self, response):
        """Mock the management HTTP client's POST method."""
        with self._patch_ctx("post", response, "mgmt") as mock:
            yield mock

    @contextmanager
    def mock_mgmt_get(self, response):
        with self._patch_ctx("get", response, "mgmt") as mock:
            yield mock

    @contextmanager
    def mock_mgmt_delete(self, response):
        with self._patch_ctx("delete", response, "mgmt") as mock:
            yield mock

    # --- Internals ---

    def _patch_ctx(self, http_method: str, response, target: str):
        """
        Return a context manager that patches the right HTTP layer.

        Sync mode: patches httpx.{method} (module-level function) — same depth
        as existing tests, preserving coverage of HTTPClient internals.

        Async mode: patches _async_client.{method} on the AsyncHTTPClient instance
        — equivalent depth for the async path.
        """
        if self.mode == "sync":
            return patch(f"httpx.{http_method}", return_value=response)
        else:
            http_client = (
                self._raw._auth_http if target == "auth" else self._raw._mgmt_http
            )
            return patch.object(
                http_client._async_client,
                http_method,
                AsyncMock(return_value=response),
            )


# --- Fixtures ---

@pytest.fixture(params=["sync", "async"])
def descope_client(request):
    """
    Parametrized fixture that yields a UnifiedClient wrapping either
    DescopeClient (sync) or AsyncDescopeClient (async).

    Runs every consuming test twice: once per mode.
    """
    os.environ["DESCOPE_BASE_URI"] = DEFAULT_BASE_URL
    if request.param == "sync":
        raw = DescopeClient(DUMMY_PROJECT_ID, PUBLIC_KEY_DICT)
        yield UnifiedClient("sync", raw)
    else:
        raw = AsyncDescopeClient(DUMMY_PROJECT_ID, PUBLIC_KEY_DICT)
        yield UnifiedClient("async", raw)


@pytest.fixture(params=["sync", "async"])
def mgmt_client(request):
    """Same as descope_client but with a management key for management API tests."""
    os.environ["DESCOPE_BASE_URI"] = DEFAULT_BASE_URL
    if request.param == "sync":
        raw = DescopeClient(DUMMY_PROJECT_ID, PUBLIC_KEY_DICT, False, DUMMY_MGMT_KEY)
        yield UnifiedClient("sync", raw)
    else:
        raw = AsyncDescopeClient(DUMMY_PROJECT_ID, PUBLIC_KEY_DICT, False, DUMMY_MGMT_KEY)
        yield UnifiedClient("async", raw)
```

---

## Structure of a unified test file

Each existing test class is split into two logical sections:

1. **Pure function tests** (`def`, no fixture) — test `_compose_*` static methods directly.
   These are sync-only by nature (pure computation, no client needed). They stay exactly
   as they are, just converted from `assertEqual/assertRaises` to `assert/pytest.raises`.

2. **Behavioral tests** (`async def`, uses `descope_client` fixture) — parametrized
   over sync and async. Test every public method: success path, validation failures,
   and HTTP error handling.

### Before → After example (`test_otp.py`)

**Before (current pattern):**
```python
class TestOTP(common.DescopeTest):
    def setUp(self):
        self.client = DescopeClient(self.dummy_project_id, self.public_key_dict)

    def test_compose_signin_url(self):
        self.assertEqual(OTP._compose_signin_url(DeliveryMethod.EMAIL), "/v1/auth/otp/signin/email")

    def test_sign_up(self):
        with patch("httpx.post") as mock_post:
            my_mock_response = mock.Mock()
            my_mock_response.is_success = True
            my_mock_response.json.return_value = {"maskedEmail": "t***@example.com"}
            mock_post.return_value = my_mock_response
            self.assertEqual(
                "t***@example.com",
                self.client.otp.sign_up(DeliveryMethod.EMAIL, "dummy@dummy.com", user),
            )
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{EndpointsV1.sign_up_auth_otp_path}/email",
                headers={...},
                json={...},
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
                ...
            )
```

**After (unified pattern):**
```python
# --- Pure function tests (no client, no parametrization) ---

def test_compose_signin_url():
    assert OTP._compose_signin_url(DeliveryMethod.EMAIL) == "/v1/auth/otp/signin/email"
    assert OTP._compose_signin_url(DeliveryMethod.SMS) == "/v1/auth/otp/signin/sms"

def test_compose_update_user_phone_body():
    result = OTP._compose_update_user_phone_body("dummy@dummy.com", "+11111111", False, True)
    assert result == {"loginId": "dummy@dummy.com", "phone": "+11111111",
                      "addToLoginIDs": False, "onMergeUseExisting": True}

# --- Behavioral tests (parametrized sync + async) ---

class TestOTPSignUp:
    async def test_invalid_email_raises(self, descope_client):
        with pytest.raises(AuthException):
            await descope_client.invoke(
                descope_client.otp.sign_up(DeliveryMethod.EMAIL, "not-an-email", {})
            )

    async def test_sign_up_success(self, descope_client):
        resp = make_response({"maskedEmail": "t***@example.com"})
        with descope_client.mock_post(resp):
            result = await descope_client.invoke(
                descope_client.otp.sign_up(DeliveryMethod.EMAIL, "dummy@dummy.com",
                                           {"email": "dummy@dummy.com"})
            )
        assert result == "t***@example.com"

    async def test_http_error_raises(self, descope_client):
        resp = make_response({}, status=500)
        with descope_client.mock_post(resp):
            with pytest.raises(AuthException):
                await descope_client.invoke(
                    descope_client.otp.sign_up(DeliveryMethod.EMAIL, "dummy@dummy.com",
                                               {"email": "dummy@dummy.com"})
                )

    async def test_sign_up_with_signup_options(self, descope_client):
        resp = make_response({"maskedEmail": "t***@example.com"})
        with descope_client.mock_post(resp) as mock:
            result = await descope_client.invoke(
                descope_client.otp.sign_up(
                    DeliveryMethod.EMAIL, "dummy@dummy.com",
                    {"email": "dummy@dummy.com"},
                    SignUpOptions(template_options={"bla": "blue"}),
                )
            )
        assert result == "t***@example.com"
        assert mock.called   # verify HTTP was called at all; body structure tested in test_http_client.py
```

The `assert_called_with(full_url, headers, json, ...)` checks from current tests are
**not** ported to the unified tests. They move to `test_http_client.py` and
`test_async_http_client.py` where they belong — testing HTTP mechanics, not business logic.
Any body-structure assertions that are purely about auth method logic (e.g., that
`templateOptions` is included when `SignUpOptions` has `template_options`) belong in the
unified test and are verified by checking `mock.call_args.kwargs["json"]` or similar.

---

## The 10%: mode-specific tests (keep as-is or new)

These tests are NOT unified and live in their own files.

### Tests that stay sync-only (existing files, converted to plain pytest)

**`tests/test_descope_client.py`**
- `DescopeClient.__init__` validation: missing project_id, skip_verify warning, `kwargs` rejection
- `validate_permissions`, `validate_session`, `refresh_session` (JWT validation — sync always)
- `get_last_response` in verbose mode

**`tests/test_http_client.py`** (expanded from current)
- `HTTPClient.__init__`: SSL context setup, base_url resolution per region
- `HTTPClient.get/post/put/patch/delete`: verify `httpx.*` is called with exact URL, headers, JSON, timeout, verify
- Retry logic: responses with status 503/521 trigger retries with correct delays
- Rate limit exception on 429
- `AuthException` on non-2xx
- `get_last_response` in verbose mode (thread-local)

### New async-only tests

**`tests/test_async_http_client.py`**
- `AsyncHTTPClient.__init__`: creates `httpx.AsyncClient` with correct verify/timeout
- `AsyncHTTPClient.get/post/put/patch/delete`: verify `_async_client.*` called with correct URL, headers, JSON
- Async retry logic: retries on same status codes, uses `asyncio.sleep` not `time.sleep`
- Rate limit and error raising (same as sync variant)
- `aclose()`: calls `_async_client.aclose()`
- `__aenter__`/`__aexit__`: context manager protocol

**`tests/test_async_descope_client.py`**
- `AsyncDescopeClient.__init__`: same validation as `DescopeClient`
- `AsyncDescopeClient` as context manager: `async with ... as client:` pattern
- `aclose()`: both http clients are closed
- Verify async properties return `AsyncOTP`, `AsyncMGMT`, etc.

---

## Migration strategy: from `unittest.TestCase` to plain pytest

The existing tests use `unittest.TestCase` with `assertEqual`, `assertRaises`, `setUp`.
Migrate each file systematically:

| Old | New |
|-----|-----|
| `class TestFoo(common.DescopeTest):` | `class TestFoo:` (plain pytest class) |
| `def setUp(self): self.client = ...` | Remove — client comes from `descope_client` fixture |
| `self.assertEqual(a, b)` | `assert a == b` |
| `self.assertRaises(Ex, fn, arg)` | `with pytest.raises(Ex): fn(arg)` |
| `self.assertIsNotNone(x)` | `assert x is not None` |
| `def test_*(self):` | `async def test_*(self, descope_client):` |
| `with patch("httpx.post") as mock:` | `with descope_client.mock_post(resp) as mock:` |
| `client.otp.sign_in(...)` | `await descope_client.invoke(descope_client.otp.sign_in(...))` |

The `_compose_*` static method tests don't use a client at all. Convert them to
module-level `def test_*()` functions (no class, no fixture) — they need zero changes
beyond the `assertEqual` → `assert` syntax.

---

## Coverage maintenance strategy

With 98% minimum coverage enforced, here is how each file's coverage is maintained:

| Code path | Covered by |
|-----------|-----------|
| `HTTPClient.get/post/put/patch/delete` | `test_http_client.py` (expanded, asserts on full httpx call) |
| `HTTPClient._execute_with_retry`, retry delays | `test_http_client.py` (mock httpx to return 503 repeatedly) |
| `AsyncHTTPClient.get/post/put/patch/delete` | `test_async_http_client.py` (patches `_async_client.*`) |
| `AsyncHTTPClient._async_execute_with_retry` | `test_async_http_client.py` |
| `AsyncHTTPClient.aclose`, `__aenter__/__aexit__` | `test_async_http_client.py` |
| Every auth method's business logic (sign_in, sign_up, verify, update) | Unified tests × 2 (both params) |
| Every management method | Unified tests × 2 |
| `DescopeClient.__init__` validation | `test_descope_client.py` (sync-only) |
| `AsyncDescopeClient.__init__` validation | `test_async_descope_client.py` (async-only) |
| `Auth.validate_session`, JWT validation | `test_auth.py` — these tests are sync-only and need no changes |
| `future_utils.py` | File is deleted; `test_future_utils.py` is also deleted |

The current `test_future_utils.py` (added in Stage 0) is deleted along with the module it tests.

The key insight: unified parametrized tests touch every auth/management method TWICE
(once per mode), so coverage for those paths is doubled. The HTTP client tests now need
to be more comprehensive to cover paths previously covered by the `assert_called_with`
checks in auth method tests.

---

## File change summary

| File | Action |
|------|--------|
| `tests/conftest.py` | **Create** — `UnifiedClient`, `make_response`, all fixtures |
| `tests/common.py` | Keep minimal — `DEFAULT_BASE_URL`, `default_headers` only (remove `DescopeTest` base class once migration complete) |
| `tests/test_future_utils.py` | **Delete** (module deleted) |
| `tests/test_http_client.py` | Expand: add full `assert_called_with` tests migrated from auth method tests |
| `tests/test_async_http_client.py` | **Create** — async transport tests |
| `tests/test_async_descope_client.py` | **Create** — lifecycle + init tests |
| `tests/test_descope_client.py` | Keep sync-only, convert to plain pytest |
| `tests/test_auth.py` | Keep sync-only (JWT validation is never async), convert syntax |
| `tests/test_otp.py` | Unify: static method tests stay plain; behavioral tests use `descope_client` fixture |
| `tests/test_totp.py` | Same |
| `tests/test_magiclink.py` | Same |
| `tests/test_enchantedlink.py` | Same |
| `tests/test_oauth.py` | Same |
| `tests/test_saml.py` | Same |
| `tests/test_sso.py` | Same |
| `tests/test_webauthn.py` | Same |
| `tests/test_password.py` | Same |
| `tests/management/conftest.py` | **Create** — `mgmt_client` fixture re-exported |
| `tests/management/test_user.py` | Unify using `mgmt_client` fixture |
| `tests/management/test_access_key.py` | Same |
| `tests/management/test_audit.py` | Same |
| `tests/management/test_authz.py` | Same |
| `tests/management/test_descoper.py` | Same |
| `tests/management/test_fga.py` | Same |
| `tests/management/test_flow.py` | Same |
| `tests/management/test_group.py` | Same |
| `tests/management/test_jwt.py` | Same |
| `tests/management/test_mgmtkey.py` | Same |
| `tests/management/test_outbound_application.py` | Same |
| `tests/management/test_permission.py` | Same |
| `tests/management/test_project.py` | Same |
| `tests/management/test_role.py` | Same |
| `tests/management/test_sso_application.py` | Same |
| `tests/management/test_sso_settings.py` | Same |
| `tests/management/test_tenant.py` | Same |

---

## Edge cases where unified tests need special care

### Cookie-based responses (`generate_jwt_response`)

Some methods (OTP `verify_code`, TOTP `sign_in_code`, etc.) extract a refresh token
from `response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)`. The `make_response`
helper supports this:

```python
resp = make_response(
    json_data={"sessionJwt": "...", "refreshJwt": "...", ...},
    cookies={REFRESH_SESSION_COOKIE_NAME: "refresh-token-value"},
)
```

### Methods that call `get_last_response` / verbose mode

These are sync-specific (thread-local). Test in `test_descope_client.py` / `test_http_client.py` only.

### `EnchantedLink` polling

`enchantedlink.get_session` polls and may block. Mock `httpx.get` to return immediately.
Unified test works as normal — the polling loop is still exercised.

### Rate limit exceptions

`make_response` can produce a 429 response. The `UnifiedClient.mock_post` machinery
handles it — both sync and async `HTTPClient` call `_raise_from_response` which raises
`RateLimitException`. The unified test:

```python
async def test_rate_limit(self, descope_client):
    resp = make_response(
        {"errorCode": 429, "errorDescription": "Too many requests"},
        status=429,
    )
    resp.headers = {"X-Rate-Limit-Retry-After-Seconds": "60"}
    with descope_client.mock_post(resp):
        with pytest.raises(RateLimitException):
            await descope_client.invoke(descope_client.otp.sign_in(...))
```

---

## Invariants

1. **No test logic is duplicated** — each behavioral test exists once and runs twice (sync + async params)
2. **`_compose_*` static method tests remain sync-only** — they test pure functions, not clients
3. **HTTP transport mechanics are tested in dedicated files** — not in auth/management test files
4. **`asyncio_mode = "auto"`** means no decorator boilerplate on any test
5. **`make_response()` is the single factory** — no inline `MagicMock` construction in test bodies
6. **The `UnifiedClient` fixture teardown** is handled by pytest automatically (the fixture is a generator via `yield`)
