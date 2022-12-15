# Descope SDK for Python

The Descope SDK for python provides convenient access to the Descope user management and authentication API
for a backend written in python. You can read more on the [Descope Website](https://descope.com).

## Requirements

The SDK supports Python 3.6 and above.

## Installing the SDK

Install the package with:

```bash
pip install descope
```

## Usage

A Descope `Project ID` is required to initialize the SDK. Find it on the
[project page in the Descope Console](https://app.descope.com/settings/project).

```python
from descope import DescopeClient

# Initialized after setting the DESCOPE_PROJECT_ID env var
descope_client = DescopeClient()

# ** Or directely **
descope_client = DescopeClient(project_id="<Project ID>")
```

## Code Samples

You can find various usage samples in the [samples folder](https://github.com/descope/python-sdk/blob/main/samples).

## API

Here are some examples how to manage and authenticate users:

### OTP Authentication

Send a user a one-time password (OTP) using your preferred delivery method (_email, SMS, Whatsapp message_). An email address or phone number must be provided accordingly.

The user can either `sign up`, `sign in` or `sign up or in`

```python
from descope import DeliveryMethod

# Every user must have an identifier. All other user information is optional
email = "desmond@descope.com"
user = {"name": "Desmond Copeland", "phone": "212-555-1234", "email": email}
descope_client.otp.sign_up(method=DeliveryMethod.EMAIL, identifier=email, user=user)
```

The user will receive a code using the selected delivery method. Verify that code using:

```python
jwt_response = descope_client.otp.verify_code(
    method=DeliveryMethod.EMAIL, identifier=email, code=value
)
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### Session Validation

Every secure request performed between your client and server needs to be validated. The client sends
the session and refresh tokens with every request, and they are validated using:

```python
descope_client.validate_session_request(session_token, refresh_token)
```

Usually, the tokens can be passed via HTTP headers or via a cookie. The implementation can
defer according to your framework of choice. See our [samples](#code-samples) for a few examples.

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

# ** Or directely **
descope_client = DescopeClient(project_id="<Project ID>", management_key="<Management Key>")
```

### Manage Authorization

You can create, update, delete or load roles and permissions.

```Python
# Create a new permission
permission_name = "New Permission"
descope_client.mgmt.permission.create(permission_name, "User allowed to perform some action")

#Create a role using that permission
descope_client.mgmt.role.create(
    "New Role", "Users belonging to some group", permission_names=[permission_name]
)

```

## Learn More

To learn more please see the [Descope Documentation and API reference page](https://docs.descope.com/).

## Contact Us

If you need help you can email [Descope Support](mailto:support@descope.com)

## License

The Descope SDK for Python is licensed for use under the terms and conditions of the [MIT license Agreement](https://github.com/descope/python-sdk/blob/main/LICENSE).
