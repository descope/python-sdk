# Async Rollout Plan — python-sdk

## Current state (as of Stage 0)
- `future_utils.py` exists with `then`, `wrap`, `resolve` helpers
- `HTTPClient` supports an async transport path gated by `async_mode_experimental` — Stage 0 complete
- `DescopeClient` accepts the flag, forwards it, and exposes `aclose()` / `__aenter__` / `__aexit__` for lifecycle management

---

## Stage 0 — Foundation: async HTTP transport (1 PR + 1 test PR)

**PR 0a — Implementation:**
- Add `httpx.AsyncClient` (persistent, per-instance) alongside the existing synchronous path
- Add `async def _async_execute_with_retry(request_fn)` mirroring the sync retry loop
- Each public method accepts an explicit `async_mode: bool = False` parameter; passing `True` delegates to the async path and returns a coroutine; the class-level `async_mode_experimental` flag is stored but inert until the final global-rollout stage
- No callers change yet — this PR is purely internal to `HTTPClient`

**PR 0b — Tests:**
- Unit tests asserting async mode methods return coroutines (`asyncio.iscoroutine`)
- Verify sync mode is completely unaffected (all existing tests continue to pass unchanged)
- Test async retry logic (mock 503s, assert delays and retry count)

---

## Stage 1–9 — Auth methods (one file per PR pair)

**Pattern for every auth method file:**

```python
# Before
response = self._http.post(uri, body=body)
return Auth.extract_masked_address(response.json(), method)

# After (using then from future_utils)
from descope.future_utils import then
response = self._http.post(uri, body=body)
return then(response, lambda r: Auth.extract_masked_address(r.json(), method))
```

When the HTTP client returns a plain `httpx.Response` (sync mode), `then` applies the lambda immediately and returns the final value — zero behaviour change. When it returns a coroutine (async mode), `then` returns a new coroutine that awaits it and applies the lambda.

Rollout order (each is one implementation PR + one test PR):

| Stage | File | Methods |
|-------|------|---------|
| 1 | `authmethod/otp.py` | sign\_in, sign\_up, sign\_up\_or\_in, verify\_code, update\_user\_email, update\_user\_phone |
| 2 | `authmethod/magiclink.py` | sign\_in, sign\_up, sign\_up\_or\_in, verify, update\_user\_email, update\_user\_phone |
| 3 | `authmethod/enchantedlink.py` | sign\_in, sign\_up, sign\_up\_or\_in, verify, get\_session, update\_user\_email, update\_user\_phone |
| 4 | `authmethod/oauth.py` | start, exchange\_token, update\_user |
| 5 | `authmethod/password.py` | sign\_in, sign\_up, send\_reset, update, replace, get\_policy |
| 6 | `authmethod/totp.py` | sign\_in, sign\_up, sign\_up\_or\_in, update\_user, verify |
| 7 | `authmethod/webauthn.py` | sign\_in\_start/finish, sign\_up\_start/finish, update\_user\_start/finish |
| 8 | `authmethod/saml.py` + `sso.py` | start methods |
| 9 | `auth.py` | validate\_session, refresh\_session, exchange\_access\_key (I/O-bound JWKS fetch) |

---

## Stage 10–N — Management files (one file per PR pair)

Same `then()` wrapping pattern. Suggested order by impact:

| Stage | File |
|-------|------|
| 10 | `management/user.py` |
| 11 | `management/access_key.py` |
| 12 | `management/tenant.py` |
| 13 | `management/role.py` + `permission.py` |
| 14 | `management/audit.py` |
| 15 | `management/authz.py` + `management/fga.py` |
| 16 | `management/sso_settings.py` + `management/sso_application.py` |
| 17 | `management/flow.py` + `management/jwt.py` |
| 18 | `management/group.py` + `management/project.py` + remaining files |

---

## Final stage — Global setting (future, after all stages done)

Once every file is converted, add a class-level `async_mode` property to `DescopeClient` that applies to all methods at once, and graduate the feature out of experimental. The per-file opt-in PRs make this final step trivial since all callers already use `then()`.

---

## Invariants throughout
- Sync callers are **never broken** at any stage — `then(sync_result, fn)` is identical to `fn(sync_result)`
- No new public API surface until the global-setting stage
- Each implementation PR is independently reviewable and rollback-safe
- Test PRs always cover both sync (regression) and async (new) paths for the converted file
