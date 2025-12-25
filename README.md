# Descope SDK for Python

The Descope SDK for python provides convenient access to the Descope user management and authentication API
for a backend written in python. You can read more on the [Descope Website](https://descope.com).

## Requirements

The SDK supports Python 3.8.1 and above.

## Installing the SDK

Install the package with:

```bash
pip install descope
```

#### If you would like to use the Flask decorators, make sure to install the Flask extras:

```bash
pip install descope[Flask]
```

## Setup

A Descope `Project ID` is required to initialize the SDK. Find it on the
[project page in the Descope Console](https://app.descope.com/settings/project).

**Note:** Authentication APIs public access can be disabled via the Descope console.
If disabled, it's still possible to use the authentication API by providing a management key with
the appropriate access (`Authentication` / `Full Access`).
If not provided directly, this value is retrieved from the `DESCOPE_AUTH_MANAGEMENT_KEY` environment variable instead.
If neither values are set then any disabled authentication methods API calls will fail.

```python
from descope import DescopeClient

# Initialized after setting the DESCOPE_PROJECT_ID and DESCOPE_AUTH_MANAGEMENT_KEY env vars
descope_client = DescopeClient()

# ** Or directly (w/ optional base URL) **
descope_client = DescopeClient(
    project_id="<Project ID>",
    auth_management_key="<Descope Project Management Key>,
    base_url="<Descope Base URL>"
)
```

## Authentication Functions

These sections show how to use the SDK to perform various authentication/authorization functions:

1. [OTP Authentication](#otp-authentication)
2. [Magic Link](#magic-link)
3. [Enchanted Link](#enchanted-link)
4. [OAuth](#oauth)
5. [SSO (SAML / OIDC)](#sso-saml--oidc)
6. [TOTP Authentication](#totp-authentication)
7. [Passwords](#passwords)
8. [Session Validation](#session-validation)
9. [Roles & Permission Validation](#roles--permission-validation)
10. [Tenant selection](#tenant-selection)
11. [Logging Out](#logging-out)
12. [History](#history)
13. [My Tenants](#my-tenants)

## API Management Function

These sections show how to use the SDK to perform permission and user management functions. You will need to create an instance of `DescopeClient` by following the [Setup](#setup-1) guide, before you can use any of these functions:

1. [Manage Tenants](#manage-tenants)
2. [Manage Users](#manage-users)
3. [Manage Access Keys](#manage-access-keys)
4. [Manage SSO Setting](#manage-sso-setting)
5. [Manage Permissions](#manage-permissions)
6. [Manage Roles](#manage-roles)
7. [Query SSO Groups](#query-sso-groups)
8. [Manage Flows](#manage-flows-and-theme)
9. [Manage JWTs](#manage-jwts)
10. [Impersonate](#impersonate)
11. [Embedded links](#embedded-links)
12. [Audit](#audit)
13. [Manage FGA (Fine-grained Authorization)](#manage-fga-fine-grained-authorization)
14. [Manage Project](#manage-project)
15. [Manage SSO Applications](#manage-sso-applications)
16. [Manage Outbound Applications](#manage-outbound-applications)

If you wish to run any of our code samples and play with them, check out our [Code Examples](#code-examples) section.

If you're performing end-to-end testing, check out the [Utils for your end to end (e2e) tests and integration tests](#utils-for-your-end-to-end-e2e-tests-and-integration-tests) section. You will need to use the `DescopeClient` object created under [Setup](#setup-1) guide.

For rate limiting information, please confer to the [API Rate Limits](#api-rate-limits) section.

### OTP Authentication

Send a user a one-time password (OTP) using your preferred delivery method (_email / SMS / Voice call / WhatsApp_). An email address or phone number must be provided accordingly.

The user can either `sign up`, `sign in` or `sign up or in`

```python
from descope import DeliveryMethod

# Every user must have a login ID. All other user information is optional
email = "desmond@descope.com"
user = {"name": "Desmond Copeland", "phone": "212-555-1234", "email": email}
masked_address = descope_client.otp.sign_up(method=DeliveryMethod.EMAIL, login_id=email, user=user)
```

The user will receive a code using the selected delivery method. Verify that code using:

```python
jwt_response = descope_client.otp.verify_code(
    method=DeliveryMethod.EMAIL, login_id=email, code=value
)
session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### Magic Link

Send a user a Magic Link using your preferred delivery method (_email / SMS / Voice call / WhatsApp_).
The Magic Link will redirect the user to page where the its token needs to be verified.
This redirection can be configured in code, or generally in the [Descope Console](https://app.descope.com/settings/authentication/magiclink)

The user can either `sign up`, `sign in` or `sign up or in`

```python
from descope import DeliveryMethod

masked_address = descope_client.magiclink.sign_up_or_in(
    method=DeliveryMethod.EMAIL,
    login_id="desmond@descope.com",
    uri="http://myapp.com/verify-magic-link", # Set redirect URI here or via console
)
```

To verify a magic link, your redirect page must call the validation function on the token (`t`) parameter (`https://your-redirect-address.com/verify?t=<token>`):

```python
jwt_response = descope_client.magiclink.verify(token=token)
session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### Enchanted Link

Using the Enchanted Link APIs enables users to sign in by clicking a link
delivered to their email address. The email will include 3 different links,
and the user will have to click the right one, based on the 2-digit number that is
displayed when initiating the authentication process.

This method is similar to [Magic Link](#magic-link) but differs in two major ways:

- The user must choose the correct link out of the three, instead of having just one
  single link.
- This supports cross-device clicking, meaning the user can try to log in on one device,
  like a computer, while clicking the link on another device, for instance a mobile phone.

The Enchanted Link will redirect the user to page where the its token needs to be verified.
This redirection can be configured in code per request, or set globally in the [Descope Console](https://app.descope.com/settings/authentication/enchantedlink).

The user can either `sign up`, `sign in` or `sign up or in`

```python
resp = descope_client.enchantedlink.sign_up_or_in(
    login_id=email,
    uri="http://myapp.com/verify-enchanted-link", # Set redirect URI here or via console
)
link_identifier = resp["linkId"] # Show the user which link they should press in their email
pending_ref = resp["pendingRef"] # Used to poll for a valid session
masked_email = resp["maskedEmail"] # The email that the message was sent to in a masked format
```

After sending the link, you must poll to receive a valid session using the `pending_ref` from
the previous step. A valid session will be returned only after the user clicks the right link.

```python
i = 0
while not done and i < max_tries:
    try:
        i = i + 1
        sleep(4)
        jwt_response = descope_client.enchantedlink.get_session(pending_ref)
        done = True
    except AuthException as e: # Poll while still receiving 401 Unauthorized
        if e.status_code != 401: # Other failures means something's wrong, abort
            logging.info(f"Failed pending session, err: {e}")
            done = True

if jwt_response:
    session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
    refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
```

To verify an enchanted link, your redirect page must call the validation function on the token (`t`) parameter (`https://your-redirect-address.com/verify?t=<token>`). Once the token is verified, the session polling will receive a valid `jwt_response`.

```python
try:
    descope_client.enchantedlink.verify(token=token)
    # Token is valid
except AuthException as e:
    # Token is invalid
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### OAuth

Users can authenticate using their social logins, using the OAuth protocol. Configure your OAuth settings on the [Descope console](https://app.descope.com/settings/authentication/social). To start a flow call:

```python

descope_client.oauth.start(
    provider="google", # Choose an oauth provider out of the supported providers
    return_url="https://my-app.com/handle-oauth", # Can be configured in the console instead of here
)
```

The user will authenticate with the authentication provider, and will be redirected back to the redirect URL, with an appended `code` HTTP URL parameter. Exchange it to validate the user:

```python
jwt_response = descope_client.oauth.exchange_token(code)
session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### SSO (SAML / OIDC)

Users can authenticate to a specific tenant using SAML/OIDC based on the tenant settings. Configure your SAML/OIDC tenant settings on the [Descope console](https://app.descope.com/tenants). To start a flow call:

```python
descope_client.sso.start(
    tenant="my-tenant-ID", # Choose which tenant to log into
    return_url="https://my-app.com/handle-sso", # Can be configured in the console instead of here
)
```

The user will authenticate with the authentication provider configured for that tenant, and will be redirected back to the redirect URL, with an appended `code` HTTP URL parameter. Exchange it to validate the user:

```python
jwt_response = descope_client.sso.exchange_token(code)
session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

Note: the descope_client.saml.start(..) and descope_client.saml.exchange_token(..) functions are DEPRECATED, use the above sso functions instead

### TOTP Authentication

The user can authenticate using an authenticator app, such as Google Authenticator.
Sign up like you would using any other authentication method. The sign up response
will then contain a QR code `image` that can be displayed to the user to scan using
their mobile device camera app, or the user can enter the `key` manually or click
on the link provided by the `provisioning_url`.

Existing users can add TOTP using the `update` function.

```python
from descope import DeliveryMethod

# Every user must have a login ID. All other user information is optional
email = "desmond@descope.com"
user = {"name": "Desmond Copeland", "phone": "212-555-1234", "email": email}
totp_response = descope_client.totp.sign_up(method=DeliveryMethod.EMAIL, login_id=email, user=user)

# Use one of the provided options to have the user add their credentials to the authenticator
provisioning_url = totp_response["provisioningURL"]
image = totp_response["image"]
key = totp_response["key"]
```

There are 3 different ways to allow the user to save their credentials in
their authenticator app - either by clicking the provisioning URL, scanning the QR
image or inserting the key manually. After that, signing in is done using the code
the app produces.

```python
jwt_response = descope_client.totp.sign_in_code(
    login_id=email,
    code=code, # Code from authenticator app
)
session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

#### Deleting the TOTP Seed

Pass the loginId to the function to remove the user's TOTP seed.

```python
response = descope_client.mgmt.user.remove_totp_seed(login_id=login_id)
```

### Passwords

The user can also authenticate with a password, though it's recommended to
prefer passwordless authentication methods if possible. Sign up requires the
caller to provide a valid password that meets all the requirements configured
for the [password authentication method](https://app.descope.com/settings/authentication/password) in the Descope console.

```python
# Every user must have a login_id and a password. All other user information is optional
login_id = "desmond@descope.com"
password = "qYlvi65KaX"
user = {
    "name": "Desmond Copeland",
    "email": login_id,
}
jwt_response = descope_client.password.sign_up(
    login_id=login_id,
    password=password,
    user=user,
)
session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
```

The user can later sign in using the same login_id and password.

```python
jwt_response = descope_client.password.sign_in(login_id, password)
session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

In case the user needs to update their password, one of two methods are available: Resetting their password or replacing their password

**Changing Passwords**

_NOTE: send_reset will only work if the user has a validated email address. Otherwise password reset prompts cannot be sent._

In the [password authentication method](https://app.descope.com/settings/authentication/password) in the Descope console, it is possible to define which alternative authentication method can be used in order to authenticate the user, in order to reset and update their password.

```python
# Start the reset process by sending a password reset prompt. In this example we'll assume
# that magic link is configured as the reset method. The optional redirect URL is used in the
# same way as in regular magic link authentication.
login_id = "desmond@descope.com"
redirect_url = "https://myapp.com/password-reset"
descope_client.password.send_reset(login_id, redirect_url)
```

The magic link, in this case, must then be verified like any other magic link (see the [magic link section](#magic-link) for more details). However, after verifying the user, it is expected
to allow them to provide a new password instead of the old one. Since the user is now authenticated, this is possible via:

```python
# The refresh token is required to make sure the user is authenticated.
err = descope_client.password.update(login_id, new_password, token)
```

`update` can always be called when the user is authenticated and has a valid session.

Alternatively, it is also possible to replace an existing active password with a new one.

```python
# Replaces the user's current password with a new one
jwt_response = descope_client.password.replace(login_id, old_password, new_password)
session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
```

### Session Validation

Every secure request performed between your client and server needs to be validated. The client sends
the session and refresh tokens with every request, and they are validated using one of the following:

```python
# Validate the session. Will raise if expired
try:
    jwt_response = descope_client.validate_session(session_token)
except AuthException:
    # Session expired

# If validate_session raises an exception, you will need to refresh the session using
jwt_response = descope_client.refresh_session(refresh_token)

# Alternatively, you could combine the two and
# have the session validated and automatically refreshed when expired
jwt_response = descope_client.validate_and_refresh_session(session_token, refresh_token)
```

Choose the right session validation and refresh combination that suits your needs.

Note: all those validation apis can receive an optional 'audience' parameter that should be provided when using jwt that has the 'aud' claim.

Refreshed sessions return the same response as is returned when users first sign up / log in,
containing the session and refresh tokens, as well as all of the JWT claims.
Make sure to return the tokens from the response to the client, or updated the cookie if you're using it.

Usually, the tokens can be passed in and out via HTTP headers or via a cookie.
The implementation can defer according to your framework of choice. See our [samples](#code-samples) for a few examples.

If Roles & Permissions are used, validate them immediately after validating the session. See the [next section](#roles--permission-validation)
for more information.

### Roles & Permission Validation

When using Roles & Permission, it's important to validate the user has the required
authorization immediately after making sure the session is valid. Taking the `jwt_response`
received by the [session validation](#session-validation), call the following functions:

For multi-tenant uses:

```python
# You can validate specific permissions
valid_permissions = descope_client.validate_tenant_permissions(
    jwt_response, "my-tenant-ID", ["Permission to validate"]
)
if not valid_permissions:
    # Deny access

# Or validate roles directly
valid_roles = descope_client.validate_tenant_roles(
    jwt_response, "my-tenant-ID", ["Role to validate"]
)
if not valid_roles:
    # Deny access

# Or get the matched roles/permissions
matched_tenant_roles = descope_client.get_matched_tenant_roles(
		jwt_response, "my-tenant-ID", ["role-name1", "role-name2"]
)

matched_tenant_permissions = descope_client.get_matched_tenant_permissions(
		jwt_response, "my-tenant-ID", ["permission-name1", "permission-name2"]
)
```

When not using tenants use:

```python
# You can validate specific permissions
valid_permissions = descope_client.validate_permissions(
    jwt_response, ["Permission to validate"]
)
if not valid_permissions:
    # Deny access

# Or validate roles directly
valid_roles = descope_client.validate_roles(
    jwt_response, ["Role to validate"]
)
if not valid_roles:
    # Deny access

# Or get the matched roles/permissions
matched_roles = descope_client.get_matched_roles(
		jwt_response, ["role-name1", "role-name2"]
)

matched_permissions = descope_client.get_matched_permissions(
		jwt_response, ["permission-name1", "permission-name2"]
)
```

### Tenant selection

For a user that has permissions to multiple tenants, you can set a specific tenant as the current selected one
This will add an extra attribute to the refresh JWT and the session JWT with the selected tenant ID

```python
tenant_id_ = "t1"
jwt_response = descope_client.select_tenant(tenant_id, refresh_token)
```

### Logging Out

You can log out a user from an active session by providing their `refresh_token` for that session.
After calling this function, you must invalidate or remove any cookies you have created.

```python
descope_client.logout(refresh_token)
```

It is also possible to sign the user out of all the devices they are currently signed-in with. Calling `logout_all` will
invalidate all user's refresh tokens. After calling this function, you must invalidate or remove any cookies you have created.

```python
descope_client.logout_all(refresh_token)
```

### History

You can get the current session user history.
The request requires a valid refresh token.

```python
users_history_resp = descope_client.history(refresh_token)
for user_history in users_history_resp:
    # Do something
```

### My Tenants

You can get the current session user tenants.
The request requires a valid refresh token.
And either a boolean to receive the current selected tenant
Or a list of tenant IDs that this user is part of

```python
tenants_resp = descope_client.my_tenants(refresh_token, False, ["tenant_id"])
for tenant in tenants_resp.tenants:
    # Do something
```

## Management API

It is very common for some form of management or automation to be required. These can be performed
using the management API. Please note that these actions are more sensitive as they are administrative
in nature. Please use responsibly.

### Setup

To use the management API you'll need a `Management Key` along with your `Project ID`.
Create one in the [Descope Console](https://app.descope.com/settings/company/managementkeys).

```python
from descope import DescopeClient

# Initialized after setting the DESCOPE_PROJECT_ID and the DESCOPE_MANAGEMENT_KEY env vars
descope_client = DescopeClient()

# ** Or directly **
descope_client = DescopeClient(project_id="<Project ID>", management_key="<Management Key>")
```

### Verbose Mode for Debugging

When debugging failed API requests, you can enable verbose mode to capture HTTP response metadata like headers (`cf-ray`, `x-request-id`), status codes, and raw response bodies. This is especially useful when working with Descope support to troubleshoot issues.

```python
from descope import DescopeClient, AuthException
import logging

logger = logging.getLogger(__name__)

# Enable verbose mode during client initialization
client = DescopeClient(
    project_id="<Project ID>",
    management_key="<Management Key>",
    verbose=True  # Enable response metadata capture
)

try:
    # Make any API call
    client.mgmt.user.create(
        login_id="test@example.com",
        email="test@example.com"
    )
except AuthException as e:
    # Access the last response metadata for debugging
    response = client.get_last_response()
    if response:
        logger.error(f"Request failed with status {response.status_code}")
        logger.error(f"cf-ray: {response.headers.get('cf-ray')}")
        logger.error(f"x-request-id: {response.headers.get('x-request-id')}")
        logger.error(f"Response body: {response.text}")

        # Provide cf-ray to Descope support for debugging
        print(f"Please provide this cf-ray to support: {response.headers.get('cf-ray')}")
```

**Important Notes:**
- Verbose mode is **disabled by default** (no performance impact when not needed)
- When enabled, only the **most recent** HTTP response is stored
- `get_last_response()` returns `None` when verbose mode is disabled
- The response object provides dict-like access to JSON data while also exposing HTTP metadata

**Available metadata on response objects:**
- `response.headers` - HTTP response headers (dict-like object)
- `response.status_code` - HTTP status code (int)
- `response.text` - Raw response body as text (str)
- `response.url` - Request URL (str)
- `response.ok` - Whether status code is < 400 (bool)
- `response.json()` - Parsed JSON response (dict/list)
- `response["key"]` - Dict-like access to JSON data (for backward compatibility)

For a complete example, see [samples/verbose_mode_example.py](https://github.com/descope/python-sdk/blob/main/samples/verbose_mode_example.py).

### Manage Tenants

You can create, update, delete or load tenants:

```Python
# You can optionally set your own ID when creating a tenant
descope_client.mgmt.tenant.create(
    name="My First Tenant",
    id="my-custom-id", # This is optional.
    self_provisioning_domains=["domain.com"],
    custom_attributes={"attribute-name": "value"},
)

# Update will override all fields as is. Use carefully.
descope_client.mgmt.tenant.update(
    id="my-custom-id",
    name="My First Tenant",
    self_provisioning_domains=["domain.com", "another-domain.com"],
    custom_attributes={"attribute-name": "value"},
)

# Managing the tenant's settings
# Getting the settings
descope_client.mgmt.tenant.load_settings(id="my-custom-id")

# updating the settings
descope_client.mgmt.tenant.update_settings(id="my-custom-id", self_provisioning_domains=["domain.com"], session_settings_enabled=True, refresh_token_expiration=1, refresh_token_expiration_unit="hours")


# Tenant deletion cannot be undone. Use carefully.
# Pass true to cascade value, in case you want to delete all users/keys associated only with this tenant
descope_client.mgmt.tenant.delete(id="my-custom-id", cascade=False)

# Load tenant by id
tenant_resp = descope_client.mgmt.tenant.load("my-custom-id")

# Load all tenants
tenants_resp = descope_client.mgmt.tenant.load_all()
tenants = tenants_resp["tenants"]
    for tenant in tenants:
        # Do something

# search all tenants
tenants_resp = descope_client.mgmt.tenant.search_all(ids=["id1"], names=["name1"], custom_attributes={"k1":"v1"}, self_provisioning_domains=["spd1"])
tenants = tenants_resp["tenants"]
    for tenant in tenants:
        # Do something
```

### Manage Users

You can create, update, patch, delete or load users, as well as setting new password, expire password and search according to filters:

```Python
# A user must have a login ID, other fields are optional.
# Roles should be set directly if no tenants exist, otherwise set
# on a per-tenant basis.
descope_client.mgmt.user.create(
    login_id="desmond@descope.com",
    email="desmond@descope.com",
    display_name="Desmond Copeland",
    user_tenants=[
        AssociatedTenant("my-tenant-id", ["role-name1"]),
    ],
	sso_app_ids=["appId1"],
)

# Alternatively, a user can be created and invited via an email message.
# Make sure to configure the invite URL in the Descope console prior to using this function,
# and that an email address is provided in the information.
descope_client.mgmt.user.invite(
    login_id="desmond@descope.com",
    email="desmond@descope.com",
    display_name="Desmond Copeland",
    user_tenants=[
        AssociatedTenant("my-tenant-id", ["role-name1"]),
    ],
    sso_app_ids=["appId1"],
# You can override the project's User Invitation Redirect URL with this parameter
    invite_url="invite.me"
)

# Batch invite
descope_client.mgmt.user.invite_batch(
    users=[
        UserObj(
            login_id="desmond@descope.com",
            email="desmond@descope.com",
            display_name="Desmond Copeland",
            user_tenants=[
                AssociatedTenant("my-tenant-id", ["role-name1"]),
            ],
            custom_attributes={"ak": "av"},
			sso_app_ids=["appId1"],
        )
    ],
    invite_url="invite.me",
    send_mail=True,
    send_sms=True,
)

# Update will override all fields as is. Use carefully.
descope_client.mgmt.user.update(
    login_id="desmond@descope.com",
    email="desmond@descope.com",
    display_name="Desmond Copeland",
    user_tenants=[
        AssociatedTenant("my-tenant-id", ["role-name1", "role-name2"]),
    ],
	sso_app_ids=["appId1"],
)

# Patch will override only the set fields in the user
descope_client.mgmt.user.patch(
    login_id="desmond@descope.com",
    email="desmond@descope.com",
    display_name="Desmond Copeland",
)

# Update explicit data for a user rather than overriding all fields
descope_client.mgmt.user.update_login_id(
    login_id="desmond@descope.com",
    new_login_id="bane@descope.com"
)
descope_client.mgmt.user.update_phone(
    login_id="desmond@descope.com",
    phone="+18005551234",
    verified=True,
)
descope_client.mgmt.user.remove_tenant_roles(
    login_id="desmond@descope.com",
    tenant_id="my-tenant-id",
    role_names=["role-name1"],
)

# Set SSO applications association to a user.
user = descope_client.mgmt.user.set_sso_apps(
	login_id="desmond@descope.com",
	sso_app_ids=["appId1", "appId2"]
)

# Add SSO applications association to a user.
user = descope_client.mgmt.user.add_sso_apps(
	login_id="desmond@descope.com",
	sso_app_ids=["appId1", "appId2"]
)

# Remove SSO applications association from a user.
user = descope_client.mgmt.user.remove_sso_apps(
	login_id="desmond@descope.com",
	sso_app_ids=["appId1", "appId2"]
)

# User deletion cannot be undone. Use carefully.
descope_client.mgmt.user.delete("desmond@descope.com")

# Load specific user
user_resp = descope_client.mgmt.user.load("desmond@descope.com")
user = user_resp["user"]

# If needed, users can be loaded using the user ID as well
user_resp = descope_client.mgmt.user.load_by_user_id("<user-id>")
user = user_resp["user"]

# Logout user from all devices by login ID
descope_client.mgmt.user.logout_user("<login-id>")

# Logout user from all devices by user ID
descope_client.mgmt.user.logout_user_by_user_id("<user-id>")

# Load users by their user id
users_resp = descope_client.mgmt.user.load_users(user_ids=["<user-id>"])
users = users_resp["users"]
    for user in users:
        # Do something

# Search all users, optionally according to tenant and/or role filter
# results can be paginated using the limit and page parameters, as well as by time with the from_created_time, to_created_time, from_modified_time, and to_modified_time
users_resp = descope_client.mgmt.user.search_all(tenant_ids=["my-tenant-id"])
users = users_resp["users"]
    for user in users:
        # Do something

# Get users' authentication history
users_history_resp = descope_client.mgmt.user.history(["user-id-1", "user-id-2"])
    for user_history in users_history_resp:
        # Do something
```

#### Set or Expire User Password

You can set a new active password for a user that they can sign in with.
You can also set a temporary password that the user will be forced to change on the next login.
For a user that already has an active password, you can expire their current password, effectively requiring them to change it on the next login.

```Python

# Set a user's temporary password
descope_client.mgmt.user.set_temporary_password('<login-id>', '<some-password>');

# Set a user's password
descope_client.mgmt.user.set_active_password('<login-id>', '<some-password>');

# Or alternatively, expire a user password
descope_client.mgmt.user.expirePassword('<login-id>');
```

### Manage Access Keys

You can create, update, delete or load access keys, as well as search according to filters:

```Python
# An access key must have a name and expiration, other fields are optional.
# Roles should be set directly if no tenants exist, otherwise set
# on a per-tenant basis.
# If user_id is supplied, then authorization would be ignored, and access key would be bound to the users authorization.
# If description is supplied, then the access key will hold a descriptive text.
# If permitted_ips is supplied, then the access key can only be used from that list of IP addresses or CIDR ranges
create_resp = descope_client.mgmt.access_key.create(
    name="name",
    expire_time=1677844931,
    key_tenants=[
        AssociatedTenant("my-tenant-id", ["role-name1"]),
    ],
    description="this is my access key",
    permitted_ips=['10.0.0.1', '192.168.1.0/24'],
)
key = create_resp["key"]
cleartext = create_resp["cleartext"] # make sure to save the returned cleartext securely. It will not be returned again.

# Load a specific access key
access_key_resp = descope_client.mgmt.access_key.load("key-id")
access_key = access_key_resp["key"]

# Search all access keys, optionally according to a tenant filter
keys_resp = descope_client.mgmt.access_key.search_all_access_keys(tenant_ids=["my-tenant-id"])
keys = keys_resp["keys"]
    for key in keys:
        # Do something

# Update will override all fields as is. Use carefully.
descope_client.mgmt.access_key.update(
    id="key-id",
    name="new name",
)

# Access keys can be deactivated to prevent usage. This can be undone using "activate".
descope_client.mgmt.access_key.deactivate("key-id")

# Disabled access keys can be activated once again.
descope_client.mgmt.access_key.activate("key-id")

# Access key deletion cannot be undone. Use carefully.
descope_client.mgmt.access_key.delete("key-id")
```

Exchange the access key and provide optional access key login options:

```python
loc = AccessKeyLoginOptions(custom_claims={"k1": "v1"})
jwt_response = descope_client.exchange_access_key(
  access_key="accessKey", login_options=loc
)
```

### Manage SSO Setting

You can manage SSO settings and map SSO group roles and user attributes.

```Python
# You can load all tenant SSO settings
sso_settings_res = descope_client.mgmt.sso.load_settings("tenant-id")

# import based on your configuration needs:
from descope import (
    SSOOIDCSettings,
    OIDCAttributeMapping,
    SSOSAMLSettings,
    AttributeMapping,
    RoleMapping,
    SSOSAMLSettingsByMetadata
)

# You can Configure SSO SAML settings for a tenant manually.
settings = SSOSAMLSettings(
	idp_url="https://dummy.com/saml",
	idp_entity_id="entity1234",
	idp_cert="my certificate",
	attribute_mapping=AttributeMapping(
		name="name",
		given_name="givenName",
		middle_name="middleName",
		family_name="familyName",
		picture="picture",
		email="email",
		phone_number="phoneNumber",
		group="groups"
	),
	role_mappings=[RoleMapping(groups=["grp1"], role="rl1")],
)
descope_client.mgmt.sso.configure_saml_settings(
	tenant_id, # Which tenant this configuration is for
	settings, # The SAML settings
	redirect_url="https://your.domain.com", # Global redirection after successful authentication
    domains=["tenant-users.com"] # Users authentication with these domains will be logged in to this tenant
)

# You can Configure SSO SAML settings for a tenant by fetching them from an IDP metadata URL.
settings = SSOSAMLSettingsByMetadata(
	idp_metadata_url="https://dummy.com/metadata",
	attribute_mapping=AttributeMapping(
		name="myName",
		given_name="givenName",
		middle_name="middleName",
		family_name="familyName",
		picture="picture",
		email="email",
		phone_number="phoneNumber",
		group="groups"
	),
	role_mappings=[RoleMapping(groups=["grp1"], role="rl1")],
)
descope_client.mgmt.sso.configure_saml_settings_by_metadata(
	tenant_id, # Which tenant this configuration is for
	settings,  # The SAML settings
	redirect_url="https://your.domain.com", # Global redirection after successful authentication
    domains=["tenant-users.com"] # Users authentication with these domains will be logged in to this tenant
)

# You can Configure SSO OIDC settings for a tenant manually.
settings = SSOOIDCSettings(
	name="myProvider",
	client_id="myId",
	client_secret="secret",
    redirect_url="https://your.domain.com",
	auth_url="https://dummy.com/auth",
	token_url="https://dummy.com/token",
	user_data_url="https://dummy.com/userInfo",
	scope=["openid", "profile", "email"],
	attribute_mapping=OIDCAttributeMapping(
		login_id="subject",
		name="name",
		given_name="givenName",
		middle_name="middleName",
		family_name="familyName",
		email="email",
		verified_email="verifiedEmail",
		username="username",
		phone_number="phoneNumber",
		verified_phone="verifiedPhone",
		picture="picture"
	)
)
descope_client.mgmt.sso.configure_oidc_settings(
	tenant_id, # Which tenant this configuration is for
	settings, # The OIDC provider settings
    domains=["tenant-users.com"] # Users authentication with these domains will be logged in to this tenant
)

# DEPRECATED (use load_settings(..) function instead)
# You can get SSO settings for a tenant
sso_settings_res = descope_client.mgmt.sso.get_settings("tenant-id")

# DEPRECATED (use configure_saml_settings(..) function instead)
# You can configure SSO settings manually by setting the required fields directly
descope_client.mgmt.sso.configure(
    tenant_id, # Which tenant this configuration is for
    idp_url="https://idp.com",
    entity_id="my-idp-entity-id",
    idp_cert="<your-cert-here>",
    redirect_url="https://your.domain.com", # Global redirection after successful authentication
    domains=["tenant-users.com"] # Users authentication with these domains will be logged in to this tenant
)

# DEPRECATED (use configure_saml_settings_by_metadata(..) function instead)
# Alternatively, configure using an SSO metadata URL
descope_client.mgmt.sso.configure_via_metadata(
    tenant_id, # Which tenant this configuration is for
    idp_metadata_url="https://idp.com/my-idp-metadata",
    redirect_url="", # Redirect URL will have to be provided in every authentication call
    domains=None # Remove the current domains configuration if a value was previously set
)

# DEPRECATED (use configure_saml_settings() or configure_saml_settings_by_metadata(..) functions instead)
# Map IDP groups to Descope roles, or map user attributes.
# This function overrides any previous mapping (even when empty). Use carefully.
descope_client.mgmt.sso.mapping(
    tenant_id, # Which tenant this mapping is for
    role_mappings = [RoleMapping(["IDP_ADMIN"], "Tenant Admin")],
    attribute_mapping=AttributeMapping(name="IDP_NAME", phone_number="IDP_PHONE"),
)
```

Note: Certificates should have a similar structure to:

```
-----BEGIN CERTIFICATE-----
Certificate contents
-----END CERTIFICATE-----
```

### Manage Permissions

You can create, update, delete or load permissions:

```Python
# You can optionally set a description for a permission.
descope_client.mgmt.permission.create(
    name="My Permission",
    description="Optional description to briefly explain what this permission allows."
)

# Update will override all fields as is. Use carefully.
descope_client.mgmt.permission.update(
    name="My Permission",
    new_name="My Updated Permission",
    description="A revised description"
)

# Permission deletion cannot be undone. Use carefully.
descope_client.mgmt.permission.delete("My Updated Permission")

# Load all permissions
permissions_resp = descope_client.mgmt.permission.load_all()
permissions = permissions_resp["permissions"]
    for permission in permissions:
        # Do something
```

### Manage Roles

You can create, update, delete or load roles:

```Python
# You can optionally set a description and associated permission for a roles.
descope_client.mgmt.role.create(
    name="My Role",
    description="Optional description to briefly explain what this role allows.",
    permission_names=["My Updated Permission"],
    tenant_id="Optionally scope this role for this specific tenant. If left empty, the role will be available to all tenants.",
    private=False  # Optional, marks this role as private role
)

# Update will override all fields as is. Use carefully.
descope_client.mgmt.role.update(
    name="My Role",
    new_name="My Updated Role",
    description="A revised description",
    permission_names=["My Updated Permission", "Another Permission"],
    tenant_id="The tenant ID to which this role is associated, leave empty, if role is a global one",
    private=True  # Optional, marks this role as private role
)

# Role deletion cannot be undone. Use carefully.
descope_client.mgmt.role.delete("My Updated Role", "<tenant_id>")

# Load all roles
roles_resp = descope_client.mgmt.role.load_all()
roles = roles_resp["roles"]
    for role in roles:
        # Do something

# Search roles
roles_resp = descope_client.mgmt.role.search(["t1", "t2"], ["r1", "r2"])
roles = roles_resp["roles"]
    for role in roles:
        # Do something
```

### Manage Flows and Theme

You can list your flows and also import and export flows and screens, or the project theme:

```Python
# List all project flows
flows_resp = descope_client.mgmt.flow.list_flows()
print(f'Total number of flows: {flows_resp["total"]}')
flows = flows_resp["flows"]
for flow in flows:
    # Do something

# Delete flows by ids
descope_client.mgmt.flow.delete_flows(
    flow_ids=["flow-1", "flow-2"],
)

# Export a selected flow by id for the flow and matching screens.
exported_flow_and_screens = descope_client.mgmt.flow.export_flow(
    flow_id="sign-up-or-in",
)

# Import a given flow and screens to the flow matching the id provided.
imported_flow_and_screens = descope_client.mgmt.flow.import_flow(
    flow_id="sign-up-or-in",
    flow={},
    screens=[]
)

# Export your project theme.
exported_theme = descope_client.mgmt.flow.export_theme()

# Import a theme to your project.
imported_theme = descope_client.mgmt.flow.import_flow(
    theme={}
)
```

### Query SSO Groups

You can query SSO groups:

```Python
# Load all groups for a given tenant id
groups_resp = descope_client.mgmt.group.load_all_groups(
    tenant_id="tenant-id",
)

# Load all groups for the given user IDs (can be found in the user's JWT)
groups_resp = descope_client.mgmt.group.load_all_groups_for_members(
    tenant_id="tenant-id",
    user_ids=["user-id-1", "user-id-2"],
)

# Load all groups for the given user's login IDs (used for sign-in)
groups_resp = descope_client.mgmt.group.load_all_groups_for_members(
    tenant_id="tenant-id",
    login_ids=["login-id-1", "login-id-2"],
)

# Load all group's members by the given group id
groups_resp = descope_client.mgmt.group.load_all_group_members(
    tenant_id="tenant-id",
    group_id="group-id,
)

for group in groups_resp:
    # Do something
```

### Manage JWTs

You can add custom claims to a valid JWT.

```python
updated_jwt = descope_client.mgmt.jwt.update_jwt(
    jwt="original-jwt",
    custom_claims={
        "custom-key1": "custom-value1",
        "custom-key2": "custom-value2"
    },
)
```

Generate a JWT for a user, simulating a signin request.

```python
jwt_response = descope_client.mgmt.jwt.sign_in(
    login_id="dummy"
)
```

Generate a JWT for a user, simulating a signup request.

```python
jwt_response = descope_client.mgmt.jwt.sign_up(
    login_id="dummy"
)
```

Generate a JWT for a user, simulating a signup or in request.

```python
jwt_response = descope_client.mgmt.jwt.sign_up_or_in(
    login_id="dummy"
)
```

### Impersonate

You can impersonate to another user
The impersonator user must have the `impersonation` permission in order for this request to work.
The response would be a refresh JWT of the impersonated user

```python
refresh_jwt = descope_client.mgmt.jwt.impersonate(
    impersonator_id="<Login ID impersonator>",
    login_id="<Login ID of impersonated person>",
    validate_consent=True,
    custom_claims={"key1":"value1"},
    tenant_id="<One of the tenants the impersonated user belongs to>"
)
```

# Note 1: The generate code/link functions, work only for test users, will not work for regular users.

# Note 2: In case of testing sign-in / sign-up operations with test users, need to make sure to generate the code prior calling the sign-in / sign-up operations.

### Embedded links

Embedded links can be created to directly receive a verifiable token without sending it.

This token can then be verified using the magic link 'verify' function, either directly or through a flow.

```python
token = descope_client.mgmt.user.generate_embedded_link("desmond@descope.com", {"key1":"value1"}, 120)
```

### Audit

You can perform an audit search for either specific values or full-text across the fields. Audit search is limited to the last 30 days.
Below are some examples. For a full list of available search criteria options, see the function documentation.

```python
# Full text search on last 10 days
audits = descope_client.mgmt.audit.search(
    text="some-text",
    from_ts=datetime.now(timezone.utc)-timedelta(days=10)
)
# Search successful logins in the last 30 days
audits = descope_client.mgmt.audit.search(actions=["LoginSucceed"])
```

You can also create audit event with data

```python
await descopeClient.management.audit.create_event(
    action="pencil.created",
    type="info", # info/warn/error
    actor_id="UXXX",
    tenant_id="tenant-id"
    data={"some": "data"}
)
```

### Manage FGA (Fine-grained Authorization)

Descope supports full relation based access control (ReBAC) using a zanzibar like schema and operations.
A schema is comprized of types (entities like documents, folders, orgs, etc.) and each type has relation definitions and permission to define relations to other types.

A simple example for a file system like schema would be:

```yaml
model AuthZ 1.0

type user

type org
  relation member: user
  relation parent: org

type folder
  relation parent: folder
  relation owner: user | org#member
  relation editor: user
  relation viewer: user

  permission can_create: owner | parent.owner
  permission can_edit: editor | can_create
  permission can_view: viewer | can_edit

type doc
  relation parent: folder
  relation owner: user | org#member
  relation editor: user
  relation viewer: user

  permission can_create: owner | parent.owner
  permission can_edit: editor | can_create
  permission can_view: viewer | can_edit
```

Descope SDK allows you to fully manage the schema and relations as well as perform simple (and not so simple) checks regarding the existence of relations.

```python
# Save schema (where schema is an str as defined above)
descope_client.mgmt.fga.save_schema(schema)

# Create a relation between a resource and user
descope_client.mgmt.fga.create_relations(
    [
        {
            "resource": "some-doc",
            "resourceType": "doc",
            "relation": "owner",
            "target": "u1",
            "targetType": "user",
        }
    ]
)

# Check if target has a relevant relation
# The answer should be true because an owner can also view
relations = descope_client.mgmt.fga.check(
    [
        {
            "resource": "some-doc",
            "resourceType": "doc",
            "relation": "owner",
            "target": "u1",
            "targetType": "user",
        }
    ]
)
```

Response times of repeated FGA `check` calls, especially in high volume scenarios, can be reduced to sub-millisecond scales by re-directing the calls to a Descope FGA Cache Proxy running in the same backend cluster as your application.
After setting up the proxy server via the Descope provided Docker image, set the `fga_cache_url` parameter to be equal to the proxy URL to enable its use in the SDK, as shown in the example below:

```python
# Initialize client with FGA cache URL
descope_client = DescopeClient(
    project_id="<Project ID>",
    management_key="<Management Key>",
    fga_cache_url="https://10.0.0.4",  # example FGA Cache Proxy URL, running inside the same backend cluster
)
```

When the `fga_cache_url` is configured, the following FGA methods will automatically use the cache proxy instead of the default Descope API:

- `save_schema`
- `create_relations`
- `delete_relations`
- `check`

Other FGA operations like `load_schema` will continue to use the standard Descope API endpoints.

### Manage Project

You can change the project name, as well as clone the current project to
create a new one.

```python
# Change the project name
descope_client.mgmt.project.change_name("new-project-name")

# Change project's tags
descope_client.mgmt.project.update_tags(["new", "python"])

# Clone the current project, including its settings and configurations.
# Note that this action is supported only with a pro license or above.
# Users, tenants and access keys are not cloned.
clone_resp = descope_client.mgmt.project.clone("new-project-name")
```

You can manage your project's settings and configurations by exporting your
project's environment. You can also import previously exported data into
the same project or a different one.

```python
# Exports the current state of the project
export = descope_client.mgmt.project.export_project()

# Import the previously exported data into the current project
descope_client.mgmt.project.import_project(export)
```

### Manage SSO Applications

You can create, update, delete or load sso applications:

```python
# Create OIDC SSO application
descope_client.mgmt.sso_application.create_oidc_application(
    name="My First sso app",
	login_page_url="http://dummy.com",
	id="my-custom-id", # This is optional.
)

# Create SAML SSO application
descope_client.mgmt.sso_application.create_saml_application(
    name="My First sso app",
	login_page_url="http://dummy.com",
	id="my-custom-id", # This is optional.
	use_metadata_info=True,
	metadata_url="http://dummy.com/metadata,
	default_relay_state="relayState",
	force_authentication=False,
	logout_redirect_url="http://dummy.com/logout",
)

# Update OIDC SSO application
# Update will override all fields as is. Use carefully.
descope_client.mgmt.sso_application.update_oidc_application(
    id="my-custom-id",
    name="My First sso app",
    login_page_url="http://dummy.com",
)

# Update SAML SSO application
# Update will override all fields as is. Use carefully.
descope_client.mgmt.sso_application.update_saml_application(
    id="my-custom-id",
    name="My First sso app",
    login_page_url="http://dummy.com",
	use_metadata_info=False,
	entity_id="ent1234",
	acs_url="http://dummy.com/acs,
	certificate="my cert"
)

# SSO application deletion cannot be undone. Use carefully.
descope_client.mgmt.sso_application.delete("my-custom-id")

# Load SSO application by id
app_resp = descope_client.mgmt.sso_application.load("my-custom-id")

# Load all SSO applications
apps_resp = descope_client.mgmt.sso_application.load_all()
apps = apps_resp["apps"]
    for app in apps:
        # Do something
```

### Manage Outbound Applications

You can create, update, delete, load outbound applications and fetch tokens for them:

```python
# Create a basic outbound application
response = descope_client.mgmt.outbound_application.create_application(
    name="my new app",
    description="my desc",
    client_secret="secret123",  # Optional
    id="my-custom-id",  # Optional
)
app_id = response["app"]["id"]

# Create a full OAuth outbound application with all parameters
from descope.management.common import URLParam, AccessType, PromptType

# Create URL parameters for authorization
auth_params = [
    URLParam("response_type", "code"),
    URLParam("client_id", "my-client-id"),
    URLParam("redirect_uri", "https://myapp.com/callback")
]

# Create URL parameters for token endpoint
token_params = [
    URLParam("grant_type", "authorization_code"),
    URLParam("client_id", "my-client-id")
]

# Create prompt types
prompts = [PromptType.LOGIN, PromptType.CONSENT]

full_app = descope_client.mgmt.outbound_application.create_application(
    name="My OAuth App",
    description="A full OAuth outbound application",
    logo="https://example.com/logo.png",
    id="my-custom-id",  # Optional custom ID
    client_secret="my-secret-key",
    client_id="my-client-id",
    discovery_url="https://accounts.google.com/.well-known/openid_configuration",
    authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
    authorization_url_params=auth_params,
    token_url="https://oauth2.googleapis.com/token",
    token_url_params=token_params,
    revocation_url="https://oauth2.googleapis.com/revoke",
    default_scopes=["https://www.googleapis.com/auth/userinfo.profile"],
    default_redirect_url="https://myapp.com/callback",
    callback_domain="myapp.com",
    pkce=True,  # Enable PKCE
    access_type=AccessType.OFFLINE,  # Request refresh tokens
    prompt=prompts
)

# Update an outbound application with all parameters
# Update will override all fields as is. Use carefully.
descope_client.mgmt.outbound_application.update_application(
    id="my-app-id",
    name="my updated app",
    description="updated description",
    logo="https://example.com/logo.png",
    client_secret="new-secret",  # Optional
    client_id="new-client-id",
    discovery_url="https://accounts.google.com/.well-known/openid_configuration",
    authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
    authorization_url_params=auth_params,
    token_url="https://oauth2.googleapis.com/token",
    token_url_params=token_params,
    revocation_url="https://oauth2.googleapis.com/revoke",
    default_scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"],
    default_redirect_url="https://myapp.com/updated-callback",
    callback_domain="myapp.com",
    pkce=True,
    access_type=AccessType.OFFLINE,
    prompt=[PromptType.LOGIN, PromptType.CONSENT, PromptType.SELECT_ACCOUNT]
)

# Delete an outbound application by id
# Outbound application deletion cannot be undone. Use carefully.
descope_client.mgmt.outbound_application.delete_application("my-app-id")

# Load an outbound application by id
app = descope_client.mgmt.outbound_application.load_application("my-app-id")

# Load all outbound applications
apps_resp = descope_client.mgmt.outbound_application.load_all_applications()
apps = apps_resp["apps"]
for app in apps:
    # Do something with each app

# Fetch user token with specific scopes
user_token = descope_client.mgmt.outbound_application.fetch_token_by_scopes(
    "my-app-id",
    "user-id",
    ["read", "write"],
    {"refreshToken": True},  # Optional
    "tenant-id"  # Optional
)

# Fetch latest user token
latest_user_token = descope_client.mgmt.outbound_application.fetch_token(
    "my-app-id",
    "user-id",
    "tenant-id",  # Optional
    {"forceRefresh": True}  # Optional
)

# Fetch tenant token with specific scopes
tenant_token = descope_client.mgmt.outbound_application.fetch_tenant_token_by_scopes(
    "my-app-id",
    "tenant-id",
    ["read", "write"],
    {"refreshToken": True}  # Optional
)

# Fetch latest tenant token
latest_tenant_token = descope_client.mgmt.outbound_application.fetch_tenant_token(
    "my-app-id",
    "tenant-id",
    {"forceRefresh": True}  # Optional
)
```

Fetch outbound application tokens using an inbound application token that includes the "outbound.token.fetch" scope (no management key required)

```python
# Fetch user token with specific scopes
user_token = descope_client.mgmt.outbound_application_by_token.fetch_token_by_scopes(
	"inbound-app-token",
    "my-app-id",
    "user-id",
    ["read", "write"],
    {"refreshToken": True},  # Optional
    "tenant-id"  # Optional
)

# Fetch latest user token
latest_user_token = descope_client.mgmt.outbound_application_by_token.fetch_token(
	"inbound-app-token",
    "my-app-id",
    "user-id",
    "tenant-id",  # Optional
    {"forceRefresh": True}  # Optional
)

# Fetch tenant token with specific scopes
tenant_token = descope_client.mgmt.outbound_application_by_token.fetch_tenant_token_by_scopes(
	"inbound-app-token",
    "my-app-id",
    "tenant-id",
    ["read", "write"],
    {"refreshToken": True}  # Optional
)

# Fetch latest tenant token
latest_tenant_token = descope_client.mgmt.outbound_application_by_token.fetch_tenant_token(
	"inbound-app-token",
    "my-app-id",
    "tenant-id",
    {"forceRefresh": True}  # Optional
)
```

### Utils for your end to end (e2e) tests and integration tests

To ease your e2e tests, we exposed dedicated management methods,
that way, you don't need to use 3rd party messaging services in order to receive sign-in/up Email, SMS, Voice call, WhatsApp, and avoid the need of parsing the code and token from them.

```Python
# User for test can be created, this user will be able to generate code/link without
# the need of 3rd party messaging services.
# Test user must have a loginId, other fields are optional.
# Roles should be set directly if no tenants exist, otherwise set
# on a per-tenant basis.
descope_client.mgmt.user.create_test_user(
    login_id="desmond@descope.com",
    email="desmond@descope.com",
    display_name="Desmond Copeland",
    user_tenants=[
        AssociatedTenant("my-tenant-id", ["role-name1"]),
    ],
)

# Search all test users, optionally according to tenant and/or role filter
# results can be paginated using the limit and page parameters
users_resp = descope_client.mgmt.user.search_all_test_users()
users = users_resp["users"]
    for user in users:
        # Do something

# Now test user got created, and this user will be available until you delete it,
# you can use any management operation for test user CRUD.
# You can also delete all test users.
descope_client.mgmt.user.delete_all_test_users()

# OTP code can be generated for test user, for example:
resp = descope_client.mgmt.user.generate_otp_for_test_user(
    DeliveryMethod.EMAIL, "login-id"
)
code = resp["code"]
# Now you can verify the code is valid (using descope_client.*.verify for example)
# login_options can be provided to set custom claims to the generated jwt.

# Same as OTP, magic link can be generated for test user, for example:
resp = descope_client.mgmt.user.generate_magic_link_for_test_user(
    DeliveryMethod.EMAIL, "login-id", ""
)
link = resp["link"]

# Enchanted link can be generated for test user, for example:
resp = descope_client.mgmt.user.generate_enchanted_link_for_test_user(
    "login-id", ""
)
link = resp["link"]
pending_ref = resp["pendingRef"]
```

## API Rate Limits

Handle API rate limits by comparing the exception to the APIRateLimitExceeded exception, which includes the RateLimitParameters map with the key "Retry-After." This key indicates how many seconds until the next valid API call can take place.

```python
try:
    descope_client.magiclink.sign_up_or_in(
        method=DeliveryMethod.EMAIL,
        login_id="desmond@descope.com",
        uri="http://myapp.com/verify-magic-link",
    )
except RateLimitException as e:
    retry_after_seconds = e.rate_limit_parameters.get(API_RATE_LIMIT_RETRY_AFTER_HEADER)
    # This variable indicates how many seconds until the next valid API call can take place.
```

## Code Samples

You can find various usage samples in the [samples folder](https://github.com/descope/python-sdk/blob/main/samples).

## Run Locally

### Prerequisites

- Python 3.8.1 or higher
- [Poetry](https://python-poetry.org) installed

### Install dependencies

```bash
poetry install
```

### Run tests

Running all tests:

```bash
poetry run pytest tests
```

Running all tests with coverage:

```bash
poetry run pytest --junitxml=/tmp/pytest.xml --cov-report=term-missing:skip-covered --cov=descope tests/ --cov-report=xml:/tmp/cov.xml
```

## Learn More

To learn more please see the [Descope Documentation and API reference page](https://docs.descope.com/).

## Contact Us

If you need help you can email [Descope Support](mailto:support@descope.com)

## License

The Descope SDK for Python is licensed for use under the terms and conditions of the [MIT license Agreement](https://github.com/descope/python-sdk/blob/main/LICENSE).
