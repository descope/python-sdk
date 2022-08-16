# Descope SDK for Python

Use the Descope ExpresSDK for Python to quickly and easily add user authentication to your application or website.

The Descope SDK for Python supports Python 3.6 and above.

# Installing the SDK

Replace any instance of `<ProjectID>` in the code below with your company's Project ID, which can be found in the [Descope console](https://app.descope.com). 

Run the following code in your project. These commands will add the Descope ExpresSDK for Python as a project dependency, and set the `DESCOPE_PROJECT_ID` variable to a valid \<ProjectID\>.

     ```code Python
    pip install Descope-Auth
    export DESCOPE_PROJECT_ID=<ProjectID>
     ```

# What do you want to do?

* [OTP](./docs/otp.md)
* [magic links](./docs/magiclink.md)

# Contributing to this repo

If you would like to contribute to this repo, follow the instructions below to set up a working developement environment. 

## Unit Testing
Simplify your unit testing by using the predefined mocks and mock objects provided with the ExpresSDK.

```code python
python -m pytest tests/*
```

1. 
2. 
3 ...

# License

The Descope ExpresSDK for Python is licensed for use under the terms and conditions of the [MIT license Agreement](https://github.com/descope/python-sdk/blob/main/LICENSE).
