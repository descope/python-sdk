import json
from unittest import mock
from unittest.mock import patch

from descope import (
    AuthException,
    DescoperAttributes,
    DescoperCreate,
    DescoperProjectRole,
    DescoperRBAC,
    DescoperRole,
    DescopeClient,
)
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from .. import common


class TestDescoper(common.DescopeTest):
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

        # Test failed flows
        with patch("requests.put") as mock_put:
            mock_put.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.descoper.create,
                [
                    DescoperCreate(
                        login_id="user1@example.com",
                    )
                ],
            )

        # Test empty descopers
        self.assertRaises(
            ValueError,
            client.mgmt.descoper.create,
            [],
        )

        # Test success flow
        with patch("requests.put") as mock_put:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{
                    "descopers": [{
                        "id": "U2111111111111111111111111",
                        "attributes": {
                            "displayName": "Test User 2",
                            "email": "user2@example.com",
                            "phone": "+123456"
                        },
                        "rbac": {
                            "isCompanyAdmin": false,
                            "tags": [],
                            "projects": [{
                                "projectIds": ["P2111111111111111111111111"],
                                "role": "admin"
                            }]
                        },
                        "status": "invited"
                    }],
                    "total": 1
                }"""
            )
            mock_put.return_value = network_resp
            resp = client.mgmt.descoper.create(
                descopers=[
                    DescoperCreate(
                        login_id="user1@example.com",
                        attributes=DescoperAttributes(
                            display_name="Test User 2",
                            phone="+123456",
                            email="user2@example.com",
                        ),
                        rbac=DescoperRBAC(
                            projects=[
                                DescoperProjectRole(
                                    project_ids=["P2111111111111111111111111"],
                                    role=DescoperRole.ADMIN,
                                )
                            ],
                        ),
                    )
                ],
            )
            descopers = resp["descopers"]
            self.assertEqual(len(descopers), 1)
            self.assertEqual(descopers[0]["id"], "U2111111111111111111111111")
            self.assertEqual(resp["total"], 1)
            mock_put.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.descoper_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "descopers": [
                        {
                            "loginId": "user1@example.com",
                            "attributes": {
                                "displayName": "Test User 2",
                                "email": "user2@example.com",
                                "phone": "+123456",
                            },
                            "sendInvite": False,
                            "rbac": {
                                "isCompanyAdmin": False,
                                "tags": [],
                                "projects": [
                                    {
                                        "projectIds": ["P2111111111111111111111111"],
                                        "role": "admin",
                                    }
                                ],
                            },
                        }
                    ]
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

        # Test failed flows
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.descoper.load,
                "descoper-id",
            )

        # Test empty id
        self.assertRaises(
            ValueError,
            client.mgmt.descoper.load,
            "",
        )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{
                    "descoper": {
                        "id": "U2222222222222222222222222",
                        "attributes": {
                            "displayName": "Test User 2",
                            "email": "user2@example.com",
                            "phone": "+123456"
                        },
                        "rbac": {
                            "isCompanyAdmin": false,
                            "tags": [],
                            "projects": [{
                                "projectIds": ["P2111111111111111111111111"],
                                "role": "admin"
                            }]
                        },
                        "status": "invited"
                    }
                }"""
            )
            mock_get.return_value = network_resp
            resp = client.mgmt.descoper.load("U2222222222222222222222222")
            descoper = resp["descoper"]
            self.assertEqual(descoper["id"], "U2222222222222222222222222")
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.descoper_load_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"id": "U2222222222222222222222222"},
                allow_redirects=True,
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

        # Test failed flows
        with patch("requests.patch") as mock_patch:
            mock_patch.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.descoper.update,
                "descoper-id",
                None,
                DescoperRBAC(is_company_admin=True),
            )

        # Test empty id
        self.assertRaises(
            ValueError,
            client.mgmt.descoper.update,
            "",
        )

        # Test success flow
        with patch("requests.patch") as mock_patch:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{
                    "descoper": {
                        "id": "U2333333333333333333333333",
                        "attributes": {
                            "displayName": "Updated User",
                            "email": "user4@example.com",
                            "phone": "+1234358730"
                        },
                        "rbac": {
                            "isCompanyAdmin": true,
                            "tags": [],
                            "projects": []
                        },
                        "status": "invited"
                    }
                }"""
            )
            mock_patch.return_value = network_resp
            resp = client.mgmt.descoper.update(
                "U2333333333333333333333333",
                None,
                DescoperRBAC(is_company_admin=True),
            )
            descoper = resp["descoper"]
            self.assertEqual(descoper["id"], "U2333333333333333333333333")
            self.assertTrue(descoper["rbac"]["isCompanyAdmin"])
            mock_patch.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.descoper_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "id": "U2333333333333333333333333",
                    "rbac": {
                        "isCompanyAdmin": True,
                        "tags": [],
                        "projects": [],
                    },
                },
                allow_redirects=False,
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

        # Test failed flows
        with patch("requests.delete") as mock_delete:
            mock_delete.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.descoper.delete,
                "descoper-id",
            )

        # Test empty id
        self.assertRaises(
            ValueError,
            client.mgmt.descoper.delete,
            "",
        )

        # Test success flow
        with patch("requests.delete") as mock_delete:
            mock_delete.return_value.ok = True
            self.assertIsNone(client.mgmt.descoper.delete("U2111111111111111111111111"))
            mock_delete.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.descoper_delete_path}",
                params={"id": "U2111111111111111111111111"},
                json=None,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_list(self):
        client = DescopeClient(
            self.dummy_project_id,
            None,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.descoper.list,
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{
                    "descopers": [
                        {
                            "id": "U2444444444444444444444444",
                            "attributes": {
                                "displayName": "Admin User",
                                "email": "admin@example.com",
                                "phone": ""
                            },
                            "rbac": {
                                "isCompanyAdmin": true,
                                "tags": [],
                                "projects": []
                            },
                            "status": "enabled"
                        },
                        {
                            "id": "U2555555555555555555555555",
                            "attributes": {
                                "displayName": "Another User",
                                "email": "user3@example.com",
                                "phone": "+123456"
                            },
                            "rbac": {
                                "isCompanyAdmin": false,
                                "tags": [],
                                "projects": []
                            },
                            "status": "invited"
                        },
                        {
                            "id": "U2666666666666666666666666",
                            "attributes": {
                                "displayName": "Test User 1",
                                "email": "user2@example.com",
                                "phone": "+123456"
                            },
                            "rbac": {
                                "isCompanyAdmin": false,
                                "tags": [],
                                "projects": [{
                                    "projectIds": ["P2222222222222222222222222"],
                                    "role": "admin"
                                }]
                            },
                            "status": "invited"
                        }
                    ],
                    "total": 3
                }"""
            )
            mock_post.return_value = network_resp
            resp = client.mgmt.descoper.list()
            descopers = resp["descopers"]
            self.assertEqual(len(descopers), 3)
            self.assertEqual(resp["total"], 3)

            # First descoper - company admin
            self.assertEqual(descopers[0]["id"], "U2444444444444444444444444")
            self.assertEqual(descopers[0]["attributes"]["displayName"], "Admin User")
            self.assertTrue(descopers[0]["rbac"]["isCompanyAdmin"])
            self.assertEqual(descopers[0]["status"], "enabled")

            # Second descoper
            self.assertEqual(descopers[1]["id"], "U2555555555555555555555555")
            self.assertFalse(descopers[1]["rbac"]["isCompanyAdmin"])

            # Third descoper - with project role
            self.assertEqual(descopers[2]["id"], "U2666666666666666666666666")
            self.assertEqual(len(descopers[2]["rbac"]["projects"]), 1)

            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.descoper_list_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
