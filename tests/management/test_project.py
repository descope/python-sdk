import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from tests.testutils import SSLMatcher
from .. import common


class TestProject(common.DescopeTest):
    def setUp(self) -> None:
        super().setUp()
        self.dummy_project_id = "dummy"
        self.dummy_management_key = "key"
        self.public_key_dict = {
            "alg": "ES384",
            "crv": "P-384",
            "kid": "P2CtzUhdqpIF2ys9gg7ms06UvtC4",
            "kty": "EC",
            "use": "sig",
            "x": "pX1l7nT2turcK5_Cdzos8SKIhpLh1Wy9jmKAVyMFiOCURoj-WQX1J0OUQqMsQO0s",
            "y": "B0_nWAv2pmG_PzoH3-bSYZZzLNKUA0RoE2SH7DaS0KV4rtfWZhYd0MEr0xfdGKx0",
        }

    def test_update_name(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.project.update_name,
                "name",
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.project.update_name("new-name"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.project_update_name}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "new-name",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_update_tags(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.project.update_tags,
                "tags",
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.project.update_tags(["tag1", "tag2"]))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.project_update_tags}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tags": ["tag1", "tag2"],
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_list_projects(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.project.list_projects,
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            json_str = """
            {
                "projects": [
                    {
                        "id": "dummy",
                        "name": "hey",
                        "environment": "",
                        "tags": ["tag1", "tag2"]
                    }
                ]
            }
            """
            network_resp.json.return_value = json.loads(json_str)
            mock_post.return_value = network_resp
            resp = client.mgmt.project.list_projects()
            projects = resp["projects"]
            self.assertEqual(len(projects), 1)
            self.assertEqual(projects[0]["id"], "dummy")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.project_list_projects}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_clone(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.project.clone,
                "new-name",
                "production",
                ["apple", "banana", "cherry"],
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """
                {
                   "id":"dummy"
                }
                """
            )
            mock_post.return_value = network_resp
            resp = client.mgmt.project.clone(
                "new-name",
                "production",
                ["apple", "banana", "cherry"],
            )
            self.assertEqual(resp["id"], "dummy")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.project_clone}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "new-name",
                    "environment": "production",
                    "tags": ["apple", "banana", "cherry"],
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_export_project(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.project.export_project,
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """
                {
                   "files":{"foo":"bar"}
                }
                """
            )
            mock_post.return_value = network_resp
            resp = client.mgmt.project.export_project()
            self.assertIsNotNone(resp)
            self.assertEqual(resp["foo"], "bar")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.project_export}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_import_project(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.project.import_project,
                {
                    "foo": "bar",
                },
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            mock_post.return_value = network_resp
            files = {
                "foo": "bar",
            }
            client.mgmt.project.import_project(files)
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.project_import}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "files": {
                        "foo": "bar",
                    },
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
