import os
import platform
import unittest

try:
    from importlib.metadata import version
except ImportError:
    import pkg_resources

DEFAULT_BASE_URL = "http://127.0.0.1"


def sdk_version():
    try:
        return version("descope")
    except NameError:
        return pkg_resources.get_distribution("descope").version


default_headers = {
    "Content-Type": "application/json",
    "x-descope-sdk-name": "python",
    "x-descope-sdk-python-version": platform.python_version(),
    "x-descope-sdk-version": sdk_version(),
}


class DescopeTest(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["DESCOPE_BASE_URI"] = (
            DEFAULT_BASE_URL  # Make sure tests always running against localhost
        )
        # Some tests instantiate Auth directly; provide defaults they can use
        self.dummy_project_id = getattr(self, "dummy_project_id", "dummy")
        self.public_key_dict = getattr(
            self,
            "public_key_dict",
            {
                "alg": "ES384",
                "crv": "P-384",
                "kid": "testkid",
                "kty": "EC",
                "use": "sig",
                "x": "x",
                "y": "y",
            },
        )

    # Test helper to build a default HTTP client
    def make_http_client(self, management_key: str | None = None):
        from descope.http_client import HTTPClient

        return HTTPClient(
            project_id=self.dummy_project_id,
            timeout_seconds=60,
            secure=True,
            management_key=management_key,
        )
