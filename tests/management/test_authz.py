from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from .. import common


class TestAuthz(common.DescopeTest):
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
            self.assertRaises(AuthException, client.mgmt.authz.save_schema, {}, True)

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.authz.save_schema({"name": "kuku"}, True))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_schema_save}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={"schema": {"name": "kuku"}, "upgrade": True},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_schema(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed delete_schema
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.authz.delete_schema)

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.authz.delete_schema())
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_schema_delete}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json=None,
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load_schema(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed load_schema
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.authz.load_schema)

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.authz.load_schema())
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_schema_load}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json=None,
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_save_namespace(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed save_namespace
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.authz.save_namespace, {})

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.authz.save_namespace({"name": "kuku"}, "old", "v1")
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_ns_save}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "namespace": {"name": "kuku"},
                    "oldName": "old",
                    "schemaName": "v1",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_namespace(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed delete_namespace
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.authz.delete_namespace, "a")

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.authz.delete_namespace("a", "b"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_ns_delete}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={"name": "a", "schemaName": "b"},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_save_relation_definition(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed save_relation_definition
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, client.mgmt.authz.save_relation_definition, {}, "a"
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.authz.save_relation_definition(
                    {"name": "kuku"}, "a", "old", "v1"
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_rd_save}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "relationDefinition": {"name": "kuku"},
                    "namespace": "a",
                    "oldName": "old",
                    "schemaName": "v1",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_relation_definition(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed delete_relation_definition
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, client.mgmt.authz.delete_relation_definition, "a", "b"
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.authz.delete_relation_definition("a", "b", "c")
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_rd_delete}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={"name": "a", "namespace": "b", "schemaName": "c"},
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
            self.assertRaises(AuthException, client.mgmt.authz.create_relations, [])

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.authz.create_relations(
                    [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
                        }
                    ]
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_create}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "relations": [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
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
            self.assertRaises(AuthException, client.mgmt.authz.delete_relations, [])

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.authz.delete_relations(
                    [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
                        }
                    ]
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_delete}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "relations": [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
                        }
                    ]
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_relations_for_resources(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed delete_relations_for_resources
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, client.mgmt.authz.delete_relations_for_resources, []
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.authz.delete_relations_for_resources(["r"]))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_delete_resources}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={"resources": ["r"]},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_has_relations(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed has_relations
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.authz.has_relations, [])

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(
                client.mgmt.authz.has_relations(
                    [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
                        }
                    ]
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_has_relations}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "relationQueries": [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
                        }
                    ]
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_who_can_access(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed who_can_access
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, client.mgmt.authz.who_can_access, "a", "b", "c"
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.authz.who_can_access("a", "b", "c"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_who}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={"resource": "a", "relationDefinition": "b", "namespace": "c"},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_resource_relations(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed resource_relations
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.authz.resource_relations, "a")

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.authz.resource_relations("a"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_resource}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={"resource": "a"},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_targets_relations(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed targets_relations
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.authz.targets_relations, ["a"])

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.authz.targets_relations(["a"]))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_targets}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={"targets": ["a"]},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_what_can_target_access(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed what_can_target_access
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, client.mgmt.authz.what_can_target_access, "a"
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.authz.what_can_target_access("a"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_target_all}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={"target": "a"},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def get_modified(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed get_modified
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, client.mgmt.authz.get_modified
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.authz.get_modified())
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_get_modified}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={"since": 0},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
