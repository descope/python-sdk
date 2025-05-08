from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from .. import common


class TestFGA(common.DescopeTest):
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

    def test_save_schema(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed save_schema
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.fga.save_schema, "")

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.fga.save_schema("model AuthZ 1.0"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_save_schema}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"dsl": "model AuthZ 1.0"},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_create_relations(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed create_relations
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.fga.create_relations, [])

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.fga.create_relations(
                    [
                        {
                            "resource": "r",
                            "resourceType": "rt",
                            "relation": "rel",
                            "target": "u",
                            "targetType": "ty",
                        }
                    ]
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_create_relations}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tuples": [
                        {
                            "resource": "r",
                            "resourceType": "rt",
                            "relation": "rel",
                            "target": "u",
                            "targetType": "ty",
                        }
                    ]
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_relations(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed delete_relations
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.fga.delete_relations, [])

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.fga.delete_relations(
                    [
                        {
                            "resource": "r",
                            "resourceType": "rt",
                            "relation": "rel",
                            "target": "u",
                            "targetType": "ty",
                        }
                    ]
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_delete_relations}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tuples": [
                        {
                            "resource": "r",
                            "resourceType": "rt",
                            "relation": "rel",
                            "target": "u",
                            "targetType": "ty",
                        }
                    ]
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_check(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed has_relations
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.fga.check, [])

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(
                client.mgmt.fga.check(
                    [
                        {
                            "resource": "r",
                            "resourceType": "rt",
                            "relation": "rel",
                            "target": "u",
                            "targetType": "ty",
                        }
                    ]
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_check}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tuples": [
                        {
                            "resource": "r",
                            "resourceType": "rt",
                            "relation": "rel",
                            "target": "u",
                            "targetType": "ty",
                        }
                    ]
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load_resources_details_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )
        response_body = {
            "resourcesDetails": [
                {"resourceId": "r1", "resourceType": "type1", "displayName": "Name1"},
                {"resourceId": "r2", "resourceType": "type2", "displayName": "Name2"},
            ]
        }
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.json.return_value = response_body
            ids = [
                {"resourceId": "r1", "resourceType": "type1"},
                {"resourceId": "r2", "resourceType": "type2"},
            ]
            details = client.mgmt.fga.load_resources_details(ids)
            self.assertEqual(details, response_body["resourcesDetails"])
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_resources_load}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"resourceIdentifiers": ids},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load_resources_details_error(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            ids = [{"resourceId": "r1", "resourceType": "type1"}]
            self.assertRaises(
                AuthException,
                client.mgmt.fga.load_resources_details,
                ids,
            )

    def test_save_resources_details_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )
        details = [
            {"resourceId": "r1", "resourceType": "type1", "displayName": "Name1"}
        ]
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            client.mgmt.fga.save_resources_details(details)
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_resources_save}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"resourcesDetails": details},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_save_resources_details_error(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )
        details = [
            {"resourceId": "r1", "resourceType": "type1", "displayName": "Name1"}
        ]
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.fga.save_resources_details,
                details,
            )
