# Descope SDK for Python

The Descope SDK for python provides convenient access to the Descope user management and authentication API
for a backend written in python. You can read more on the [Descope Website](https://descope.com).

## Requirements

The SDK supports Python 3.7 and above.

## Installing the SDK

Install the package with:

```bash
pip install descope
```

## Setup

A Descope `Project ID` is required to initialize the SDK. Find it on the
[project page in the Descope Console](https://app.descope.com/settings/project).

```python
from descope import DescopeClient

# Initialized after setting the DESCOPE_PROJECT_ID env var
descope_client = DescopeClient()

# ** Or directly **
descope_client = DescopeClient(project_id="<Project ID>")
```

## Usage

Here are some examples how to manage and authenticate users:

### OTP Authentication

Send a user a one-time password (OTP) using your preferred delivery method (_email / SMS_). An email address or phone number must be provided accordingly.

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

Send a user a Magic Link using your preferred delivery method (_email / SMS_).
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

### SSO/SAML

Users can authenticate to a specific tenant using SAML or Single Sign On. Configure your SSO/SAML settings on the [Descope console](https://app.descope.com/settings/authentication/sso). To start a flow call:

```python

descope_client.saml.start(
    tenant="my-tenant-ID", # Choose which tenant to log into
    return_url="https://my-app.com/handle-saml", # Can be configured in the console instead of here
)
```

The user will authenticate with the authentication provider configured for that tenant, and will be redirected back to the redirect URL, with an appended `code` HTTP URL parameter. Exchange it to validate the user:

```python
jwt_response = descope_client.saml.exchange_token(code)
session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

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
login_id := "desmond@descope.com"
redirect_url := "https://myapp.com/password-reset"
descope_client.password.send_reset(login_id, redirect_url)
```

The magic link, in this case, must then be verified like any other magic link (see the [magic link section](#magic-link) for more details). However, after verifying the user, it is expected
to allow them to provide a new password instead of the old one. Since the user is now authenticated, this is possible via:

```python
# The refresh token is required to make sure the user is authenticated.
err := descope_client.password.update(login_id, new_password, token)
```

`update` can always be called when the user is authenticated and has a valid session.

Alternatively, it is also possible to replace an existing active password with a new one.

```python
# Replaces the user's current password with a new one
descope_client.password.replace(login_id, old_password, new_password)
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

### Manage Tenants

You can create, update, delete or load tenants:

```Python
# You can optionally set your own ID when creating a tenant
descope_client.mgmt.tenant.create(
    name="My First Tenant",
    id="my-custom-id", # This is optional.
    self_provisioning_domains=["domain.com"],
)

# Update will override all fields as is. Use carefully.
descope_client.mgmt.tenant.update(
    id="my-custom-id",
    name="My First Tenant",
    self_provisioning_domains=["domain.com", "another-domain.com"],
)

# Tenant deletion cannot be undone. Use carefully.
descope_client.mgmt.tenant.delete("my-custom-id")

# Load all tenants
tenants_resp = descope_client.mgmt.tenant.load_all()
tenants = tenants_resp["tenants"]
    for tenant in tenants:
        # Do something
```

### Manage Users

You can create, update, delete or load users, as well as search according to filters:

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
)

# Update will override all fields as is. Use carefully.
descope_client.mgmt.user.update(
    login_id="desmond@descope.com",
    email="desmond@descope.com",
    display_name="Desmond Copeland",
    user_tenants=[
        AssociatedTenant("my-tenant-id", ["role-name1", "role-name2"]),
    ],
)

# Update explicit data for a user rather than overriding all fields
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

# User deletion cannot be undone. Use carefully.
descope_client.mgmt.user.delete("desmond@descope.com")

# Load specific user
user_resp = descope_client.mgmt.user.load("desmond@descope.com")
user = user_resp["user"]

# If needed, users can be loaded using the user ID as well
user_resp = descope_client.mgmt.user.load_by_user_id("<user-id>")
user = user_resp["user"]

# Search all users, optionally according to tenant and/or role filter
# results can be paginated using the limit and page parameters
users_resp = descope_client.mgmt.user.search_all(tenant_ids=["my-tenant-id"])
users = users_resp["users"]
    for user in users:
        # Do something
```

### Manage Access Keys

You can create, update, delete or load access keys, as well as search according to filters:

```Python
# An access key must have a name and expiration, other fields are optional.
# Roles should be set directly if no tenants exist, otherwise set
# on a per-tenant basis.
create_resp = descope_client.mgmt.access_key.create(
    name="name",
    expire_time=1677844931,
    key_tenants=[
        AssociatedTenant("my-tenant-id", ["role-name1"]),
    ],
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

### Manage SSO Setting

You can manage SSO settings and map SSO group roles and user attributes.

```Python
# You can get SSO settings for a tenant
sso_settings_res = descope_client.mgmt.sso.get_settings("tenant-id")

# You can configure SSO settings manually by setting the required fields directly
descope_client.mgmt.sso.configure(
    tenant_id, # Which tenant this configuration is for
    idp_url="https://idp.com",
    entity_id="my-idp-entity-id",
    idp_cert="<your-cert-here>",
    redirect_url="https://your.domain.com", # Global redirection after successful authentication
    domain="tenant-users.com" # Users authentication with this domain will be logged in to this tenant
)

# Alternatively, configure using an SSO metadata URL
descope_client.mgmt.sso.configure_via_metadata(
    tenant_id, # Which tenant this configuration is for
    idp_metadata_url="https://idp.com/my-idp-metadata",
)

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
Certifcate contents
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
)

# Update will override all fields as is. Use carefully.
descope_client.mgmt.role.update(
    name="My Role",
    new_name="My Updated Role",
    description="A revised description",
    permission_names=["My Updated Permission", "Another Permission"]
)

# Role deletion cannot be undone. Use carefully.
descope_client.mgmt.role.delete("My Updated Role")

# Load all roles
roles_resp = descope_client.mgmt.role.load_all()
roles = roles_resp["roles"]
    for role in roles:
        # Do something
```

### Manage Flows and Theme

You can export and import your project flows and theme:

```Python
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
    jwt: "original-jwt",
    custom_claims: {
        "custom-key1": "custom-value1",
        "custom-key2": "custom-value2"
    },
)
```

### Utils for your end to end (e2e) tests and integration tests

To ease your e2e tests, we exposed dedicated management methods,
that way, you don't need to use 3rd party messaging services in order to receive sign-in/up Emails or SMS, and avoid the need of parsing the code and token from them.

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

# Note 1: The generate code/link functions, work only for test users, will not work for regular users.
# Note 2: In case of testing sign-in / sign-up operations with test users, need to make sure to generate the code prior calling the sign-in / sign-up operations.
```

## API Rate limits

Handle API rate limits by comparing the exception to the APIRateLimitExceeded exception, which includes the RateLimitParameters map with the key "Retry-After." This key indicates how many seconds until the next valid API call can take place. More information on Descope's rate limit is covered here: [Descope rate limit reference page](https://docs.descope.com/rate-limit)

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

## Learn More

To learn more please see the [Descope Documentation and API reference page](https://docs.descope.com/).

## Contact Us

If you need help you can email [Descope Support](mailto:support@descope.com)

## License

The Descope SDK for Python is licensed for use under the terms and conditions of the [MIT license Agreement](https://github.com/descope/python-sdk/blob/main/LICENSE).
