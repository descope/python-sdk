class AuthException(Exception):
    def __init__(
        self,
        status_code: int = None,
        error_type: str = None,
        error_message: str = None,
        error_url: str = None,
        **kwargs,
    ):
        self.status_code = status_code
        self.error_type = error_type
        self.error_message = error_message
        self.error_url = error_url

    def __repr__(self):
        return f"Error {self.__dict__}"

    def __str__(self):
        return str(self.__dict__)
