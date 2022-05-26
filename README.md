# Python SDK
Python library used to integrate with Descope

### Prerequisites

1. In order to initiate the AuthClient object you must specify the project ID given by Descope either by:
   - Set the `DESCOPE_PROJECT_ID` environment variable.
   - Set the project_id argument when initialization the AuthClient object.
1. When using the session validation API you may specify the public key given by Descope either by:
   - Set the `DESCOPE_PUBLIC_KEY` environment variable.
   - Set the public_key argument when initialization the AuthClient object.
   - Or keep empty to fetch matching public keys from descope services.

### Installation
Install the Descope Python SDK using the following command.
Descope Python SDK supports Python 3.6 and above

.. code-block:: python

    pip install Descope-Auth


## Usage
Use (copy-paste) the pre defined samples decorators based on your framework (Flask supported) or the api as describe below

### API
.. code-block:: python

from descope import DeliveryMethod, User, AuthClient

class DeliveryMethod(Enum):
    WHATSAPP = 1
    PHONE = 2
    EMAIL = 3

User(username: str, name: str, phone: str, email: str)

AuthClient(PROJECT_ID, PUBLIC_KEY)

sign_up_otp(method: DeliveryMethod, identifier: str, user: User)
Example:
from descope import DeliveryMethod, User, AuthClient
user = User("username", "name", "11111111111", "dummy@dummy.com")
auth_client = AuthClient(PROJECT_ID, PUBLIC_KEY)
auth_client.sign_up_otp(DeliveryMethod.EMAIL, "dummy@dummy.com", user)


sign_in_otp(method: DeliveryMethod, identifier: str)
Example:
from descope import DeliveryMethod, AuthClient
auth_client = AuthClient(PROJECT_ID, PUBLIC_KEY)
auth_client.sign_in_otp(DeliveryMethod.EMAIL, "dummy@dummy.com")

@descope_signin_otp_by_email

verify_code(method: DeliveryMethod, identifier: str, code: str)
--Upon successful verification new session cookies will returned and should be set on the response
Or one of the decorators:
@descope_verify_code_by_email
@descope_verify_code_by_phone
@descope_verify_code_by_whatsapp


Example:
from descope import DeliveryMethod, AuthClient
auth_client = AuthClient(PROJECT_ID, PUBLIC_KEY)
auth_client.verify_code(DeliveryMethod.EMAIL, "1111")
Or decorator

APP = Flask(__name__)
@APP.route("/api/verify")
@descope_verify_code_by_email
def verify():
    pass



validate_session_request(signed_token: str, signed_refresh_token: str)
Or decorator
@descope_validate_auth

Example:
from descope import AuthClient
auth_client = AuthClient(PROJECT_ID, PUBLIC_KEY)
new_valid_token = auth_client.validate_session_request('session_token', 'refresh_token')

logout(signed_token: str, signed_refresh_token: str)
Example:
from descope import AuthClient
auth_client = AuthClient(PROJECT_ID, PUBLIC_KEY)
auth_client.logout('session_token', 'refresh_token')

#### Exception
.. code-block:: python

AuthException
Example:
from descope import DeliveryMethod, AuthClient, AuthException
try:
    auth_client = AuthClient(PROJECT_ID, PUBLIC_KEY)
    auth_client.sign_in_otp(DeliveryMethod.EMAIL, "dummy@dummy.com")
except AuthException:
    #Handle exception

#
### Run The Example

1. Clone repo locally `git clone github.com/descope/python-sdk`
2. Install the requirements `pip3 install -r requirements-dev.txt`

3. export your project id a

```
export DESCOPE_PROJECT_ID=<insert here>
```

5. Run the example application `python samples/web_sample_app.py`
6. Application runs on `http://localhost:9000`
7. Now you can perform GET requests to the server api like the following example:

Signup a new user by OTP via email, verify the OTP code and then access private (authenticated) api

.. code-block

    /api/signup
    Body:
    {
        "email": "dummy@dummy.com",
        "user": {
            "username": "dummy",
            "name": "dummy",
            "phone": "11111111111",
            "email": "dummy@dummy.com"
       }
    }

    /api/verify
    Body:
    {
        "code": "111111",
        "email": "dummy@dummy.com"
    }

    ** Response will have the new generate session cookies

    /api/private
    Use the session cookies (otherwise you will get HTTP 401 - Unauthorized)

### Unit Testing
.. code-block:: python

python -m pytest tests/*
