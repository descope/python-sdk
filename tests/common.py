import os
import platform
import unittest

import pkg_resources

DEFAULT_BASE_URL = "http://127.0.0.1"

default_headers = {
    "Content-Type": "application/json",
    "x-descope-sdk-name": "python",
    "x-descope-sdk-python-version": platform.python_version(),
    "x-descope-sdk-version": pkg_resources.get_distribution("descope").version,
}


class DescopeTest(unittest.TestCase):
    def setUp(self) -> None:
        os.environ[
            "DESCOPE_BASE_URI"
        ] = DEFAULT_BASE_URL  # Make sure tests always running against localhost
