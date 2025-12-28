import json
from unittest import mock
from unittest.mock import patch

from descope import (
    DescopeClient,
    MgmtKeyProjectRole,
    MgmtKeyReBac,
    MgmtKeyStatus,
)
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from .. import common


class TestManagementKey(common.DescopeTest):
    def setUp(self) -> None:
        super().setUp()
        self.dummy_project_id = "dummy"
        self.dummy_management_key = "key"

    def test_create(self):
        client = DescopeClient(
            self.dummy_project_id,
            None,
            False,
            self.dummy_management_key,
        )

        # Test success flow
        with patch("requests.put") as mock_put:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "cleartext": "cleartext-secret",
                "key": {
                    "id": "mk1",
                    "name": "test-key",
                    "description": "test key",
                    "permittedIps": ["10.0.0.1"],
                    "status": "active",
                    "createdTime": 1764849768,
                    "expireTime": 3600,
                    "reBac": {
                        "companyRoles": ["role1"],
                        "projectRoles": [],
                        "tagRoles": [],
                    },
                    "version": 1,
                    "authzVersion": 1,
                },
            }
            mock_put.return_value = network_resp
            resp = client.mgmt.management_key.create(
                name="test-key",
                rebac=MgmtKeyReBac(company_roles=["role1"]),
                description="test key",
                expires_in=3600,
                permitted_ips=["10.0.0.1"],
            )
            self.assertEqual(resp["cleartext"], "cleartext-secret")
            key = resp["key"]
            self.assertEqual(key["name"], "test-key")
            self.assertEqual(key["description"], "test key")
            self.assertEqual(len(key["permittedIps"]), 1)
            self.assertEqual(key["permittedIps"][0], "10.0.0.1")
            self.assertEqual(key["expireTime"], 3600)
            self.assertIsNotNone(key["reBac"])
            self.assertEqual(len(key["reBac"]["companyRoles"]), 1)
            self.assertEqual(key["reBac"]["companyRoles"][0], "role1")
            mock_put.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.mgmt_key_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "test-key",
                    "description": "test key",
                    "expiresIn": 3600,
                    "permittedIps": ["10.0.0.1"],
                    "reBac": {
                        "companyRoles": ["role1"],
                    },
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_update(self):
        client = DescopeClient(
            self.dummy_project_id,
            None,
            False,
            self.dummy_management_key,
        )

        # Test success flow
        with patch("requests.patch") as mock_patch:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "key": {
                    "id": "mk1",
                    "name": "updated-key",
                    "description": "updated key",
                    "permittedIps": ["1.2.3.4"],
                    "status": "inactive",
                    "createdTime": 1764673442,
                    "expireTime": 0,
                    "reBac": {
                        "companyRoles": [],
                        "projectRoles": [],
                        "tagRoles": [],
                    },
                    "version": 22,
                    "authzVersion": 1,
                },
            }
            mock_patch.return_value = network_resp
            resp = client.mgmt.management_key.update(
                id="mk1",
                name="updated-key",
                description="updated key",
                permitted_ips=["1.2.3.4"],
                status=MgmtKeyStatus.INACTIVE,
            )
            key = resp["key"]
            self.assertEqual(key["id"], "mk1")
            self.assertEqual(key["name"], "updated-key")
            self.assertEqual(key["description"], "updated key")
            self.assertEqual(len(key["permittedIps"]), 1)
            self.assertEqual(key["permittedIps"][0], "1.2.3.4")
            self.assertEqual(key["status"], "inactive")
            mock_patch.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.mgmt_key_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "id": "mk1",
                    "name": "updated-key",
                    "description": "updated key",
                    "permittedIps": ["1.2.3.4"],
                    "status": "inactive",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load(self):
        client = DescopeClient(
            self.dummy_project_id,
            None,
            False,
            self.dummy_management_key,
        )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "key": {
                    "id": "mk1",
                    "name": "test-key",
                    "description": "a key description",
                    "status": "active",
                    "createdTime": 1764677065,
                    "expireTime": 0,
                    "permittedIps": [],
                    "reBac": {
                        "companyRoles": [],
                        "projectRoles": [],
                        "tagRoles": [],
                    },
                    "version": 1,
                    "authzVersion": 1,
                },
            }
            mock_get.return_value = network_resp
            resp = client.mgmt.management_key.load("mk1")
            key = resp["key"]
            self.assertIsNotNone(key)
            self.assertEqual(key["name"], "test-key")
            self.assertEqual(key["description"], "a key description")
            self.assertEqual(key["status"], "active")
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.mgmt_key_load_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"id": "mk1"},
                allow_redirects=True,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete(self):
        client = DescopeClient(
            self.dummy_project_id,
            None,
            False,
            self.dummy_management_key,
        )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {"total": 2}
            mock_post.return_value = network_resp
            resp = client.mgmt.management_key.delete(["mk1", "mk2"])
            self.assertEqual(resp["total"], 2)
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.mgmt_key_delete_path}",
                params=None,
                json={"ids": ["mk1", "mk2"]},
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_search(self):
        client = DescopeClient(
            self.dummy_project_id,
            None,
            False,
            self.dummy_management_key,
        )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "keys": [
                    {
                        "id": "mk1",
                        "name": "key1",
                        "description": "",
                        "status": "active",
                        "createdTime": 1764677065,
                        "expireTime": 0,
                        "permittedIps": [],
                        "reBac": {
                            "companyRoles": [],
                            "projectRoles": [],
                            "tagRoles": [],
                        },
                        "version": 1,
                        "authzVersion": 1,
                    },
                    {
                        "id": "mk2",
                        "name": "key2",
                        "description": "",
                        "status": "inactive",
                        "createdTime": 1764773205,
                        "expireTime": 1234,
                        "permittedIps": [],
                        "reBac": {
                            "companyRoles": [],
                            "projectRoles": [],
                            "tagRoles": [],
                        },
                        "version": 1,
                        "authzVersion": 1,
                    },
                ],
            }
            mock_get.return_value = network_resp
            resp = client.mgmt.management_key.search()
            keys = resp["keys"]
            self.assertIsNotNone(keys)
            self.assertEqual(len(keys), 2)
            self.assertEqual(keys[0]["id"], "mk1")
            self.assertEqual(keys[0]["name"], "key1")
            self.assertEqual(keys[0]["status"], "active")
            self.assertEqual(keys[1]["id"], "mk2")
            self.assertEqual(keys[1]["name"], "key2")
            self.assertEqual(keys[1]["status"], "inactive")
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.mgmt_key_search_path}",
                headers={
                    **common.default_headers,
                    "x-descope-project-id": self.dummy_project_id,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                allow_redirects=True,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
