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
