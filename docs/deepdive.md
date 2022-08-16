# SDK Structures, Variables

This section describes how Descope implemented the Python SDK and the variables and dictionires used throughout our code samples. It is not required reading, but it will help if you need addtional details about how the code is designed.

## user (dictionary)

The `user` dictionary stores user information as key:value pairs, and can be used to store any user information you wish to save. The following key titles are reserved and should be used only in the manner described in this SDK.

* `email` - a valid email address
* `phone` - a valid phone number

## identifier

`identifier` is the unique ID used to identify a specific user, often a phone number or email address.

## DeliveryMethod

relevant to: OTP

The `DeliveryMethod` argument describes how the OTP is sent to your user. Supported values are:

* EMAIL - OTP is sent by email
* PHONE - OTP is send as an SMS message
* WHATSAPP - OTP is sent as a WhatsApp message

When delivering an OTP to a user, Descope uses the following algorithm:

* If `DeliveryMethod = EMAIL`, Descope sends the OTP as an email to the address in user (`jwt_response["user"]["email"]`). If that key is empty or an invalid email address, Descope checks if identifer is a valid email address.
* If `DeliveryMethod = PHONE`, Descope sends the OTP as a text message to the phone in user (`jwt_response["user"]["phone"]`). If that key is empty or an invalid phone number, Descope checks if identifer is a valid phone number.
* If `DeliveryMethod = WHATSAPP`, Descope sends the OTP as a WhatsApp message to the phone in user (`jwt_response["user"]["phone"]`). If that key is empty or an invalid phone number, Descope checks if identifer is a valid phone number.

## jwt_response

The `jwt_response` dictionary contains the session token and claims, refresh token and claims, and user informatino needed to manage a session with a user. Dictionary contents includes:

* session token and claims - i.e. jwt_response[SESSION_TOKEN_NAME]["jwt"]
* refersh token and claims - jwt_response[REFRESH_SESSION_TOKEN_NAME]["jwt"]
* cookie information - jwt_response[COOKIE_DATA_NAME]
* user information - jwt_response["user"]["email"],jwt_response["user"]["phone"]

## verify_uri

relevant to: magic link

 The URI endpoint to be used for verifying magic link tokens, for example: verify_uri = "http://auth.yourcompany.com/api/verify_magiclinks". This endpoint will call the `descope_client.magiclink.verify(token)` function.
