import importlib
import importlib.util
import os
import sys
import types
import unittest

from descope import AuthException
from descope.http_client import HTTPClient


class TestHTTPClient(unittest.TestCase):
    def test_base_url_for_project_id(self):
        # short project id -> default base
        assert HTTPClient.base_url_for_project_id("short") == "https://api.descope.com"
        # long project id -> computed region
        pid = "Puse12aAc4T2V93bddihGEx2Ryhc8e5Z"
        assert HTTPClient.base_url_for_project_id(pid) == "https://api.use1.descope.com"

    def test_project_id_from_env_without_env(self):
        os.environ["DESCOPE_PROJECT_ID"] = ""
        self.assertRaises(AuthException, HTTPClient, "")

    @unittest.skipIf(
        importlib.util.find_spec("importlib.metadata") is not None,
        "Stdlib metadata available; skip fallback path test",
    )
    def test_sdk_version_import_fallback(self):
        # Simulate absence of importlib.metadata to take fallback path
        import builtins

        import descope.http_client as http_client_mod

        original_import = builtins.__import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "importlib.metadata":
                raise ImportError("simulated")
            return original_import(name, globals, locals, fromlist, level)

        # Prepare a fake pkg_resources for fallback path
        class FakeDist:
            def __init__(self, version="0.0.0"):
                self.version = version

        fake_pkg = types.ModuleType("pkg_resources")
        fake_pkg.get_distribution = lambda name: FakeDist("9.9.9")

        saved_pkg = sys.modules.get("pkg_resources")
        sys.modules["pkg_resources"] = fake_pkg

        try:
            builtins.__import__ = fake_import
            reloaded = importlib.reload(http_client_mod)
            v = reloaded.sdk_version()
            assert isinstance(v, str)
        finally:
            builtins.__import__ = original_import
            if saved_pkg is not None:
                sys.modules["pkg_resources"] = saved_pkg
            else:
                sys.modules.pop("pkg_resources", None)


if __name__ == "__main__":
    unittest.main()
