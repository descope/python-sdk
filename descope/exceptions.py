ERROR_TYPE_INVALID_ARGUMENT = "invalid argument"
ERROR_TYPE_SERVER_ERROR = "server error"
ERROR_TYPE_INVALID_PUBLIC_KEY = "invalid public key"
ERROR_TYPE_INVALID_TOKEN = "invalid token"


class AuthException(Exception):
    def __init__(
        self,
        status_code: int = None,
        error_type: str = None,
        error_message: str = None,
        **kwargs,
    ):
        self.status_code = status_code
        self.error_type = error_type
        self.error_message = error_message

    def __repr__(self):
        return f"Error {self.__dict__}"

    def __str__(self):
        return str(self.__dict__)
