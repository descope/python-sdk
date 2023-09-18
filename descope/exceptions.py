from typing import Optional

ERROR_TYPE_INVALID_ARGUMENT = "invalid argument"
ERROR_TYPE_SERVER_ERROR = "server error"
ERROR_TYPE_INVALID_PUBLIC_KEY = "invalid public key"
ERROR_TYPE_INVALID_TOKEN = "invalid token"
ERROR_TYPE_API_RATE_LIMIT = "API rate limit exceeded"

API_RATE_LIMIT_RETRY_AFTER_HEADER = "Retry-After"


class AuthException(Exception):
    def __init__(
        self,
        status_code: Optional[int] = None,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
        **kwargs,
    ):
        self.status_code = status_code
        self.error_type = error_type
        self.error_message = error_message

    def __repr__(self):
        return f"Error {self.__dict__}"

    def __str__(self):
        return str(self.__dict__)


class RateLimitException(Exception):
    def __init__(
        self,
        status_code: Optional[int] = None,
        error_type: Optional[str] = None,
        error_description: Optional[str] = None,
        error_message: Optional[str] = None,
        rate_limit_parameters: Optional[dict] = None,
        **kwargs,
    ):
        self.status_code = status_code
        self.error_type = error_type
        self.error_description = error_description
        self.error_message = error_message
        self.rate_limit_parameters = (
            {} if rate_limit_parameters is None else rate_limit_parameters
        )

    def __repr__(self):
        return f"Error {self.__dict__}"

    def __str__(self):
        return str(self.__dict__)
