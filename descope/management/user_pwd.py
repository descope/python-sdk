from typing import Optional, Union


class UserPasswordBcrypt:
    def __init__(
        self,
        hash: str,
    ):
        """
        The bcrypt hash in plaintext format, for example "$2a$..."
        """
        self.hash = hash

    def json(self):
        return {
            "bcrypt": {
                "hash": self.hash,
            },
        }


class UserPasswordFirebase:
    def __init__(
        self,
        hash: str,
        salt: str,
        saltSeparator: str,
        signerKey: str,
        memory: int,
        rounds: int,
    ):
        """
        The hash, salt, salt separator, and signer key should be base64 strings using
        standard encoding with padding.
        The memory cost value is an integer, usually between 12 to 17.
        The rounds cost value is an integer, usually between 6 to 10.
        """
        self.hash = hash
        self.salt = salt
        self.saltSeparator = saltSeparator
        self.signerKey = signerKey
        self.memory = memory
        self.rounds = rounds

    def json(self):
        return {
            "firebase": {
                "hash": self.hash,
                "salt": self.salt,
                "saltSeparator": self.saltSeparator,
                "signerKey": self.signerKey,
                "memory": self.memory,
                "rounds": self.rounds,
            },
        }


class UserPasswordPbkdf2:
    def __init__(
        self,
        hash: str,
        salt: str,
        iterations: int,
        variant: str,
    ):
        """
        The hash and salt should be base64 strings using standard encoding with padding.
        The iterations cost value is an integer, usually in the thousands.
        The hash variant should be either "sha1", "sha256", or "sha512".
        """
        self.hash = hash
        self.salt = salt
        self.iterations = iterations
        self.variant = variant

    def json(self):
        return {
            "pbkdf2": {
                "hash": self.hash,
                "salt": self.salt,
                "iterations": self.iterations,
                "type": self.variant,
            },
        }


class UserPasswordDjango:
    def __init__(
        self,
        hash: str,
    ):
        """
        The django hash in plaintext format, for example "pbkdf2_sha256$..."
        """
        self.hash = hash

    def json(self):
        return {
            "django": {
                "hash": self.hash,
            },
        }


class UserPassword:
    def __init__(
        self,
        cleartext: Optional[str] = None,
        hashed: Optional[
            Union[
                UserPasswordBcrypt,
                UserPasswordFirebase,
                UserPasswordPbkdf2,
                UserPasswordDjango,
            ]
        ] = None,
    ):
        """
        Set a UserPassword on UserObj objects when calling invite_batch to create or invite users
        with a cleartext or prehashed password. Note that only one of the two options should be set.
        """
        self.cleartext = cleartext
        self.hashed = hashed

    def json(self):
        if self.cleartext is not None:
            return {"cleartext": self.cleartext}
        elif self.hashed is not None:
            return {"hashed": self.hashed.json()}
        return None
