from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.future_utils import futu_await
from descope.management.common import MgmtV1

from tests.testutils import SSLMatcher, mock_http_call
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

    async def test_save_schema(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed save_schema
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.save_schema({}, True))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(
                await futu_await(client.mgmt.authz.save_schema({"name": "kuku"}, True))
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_schema_save}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"schema": {"name": "kuku"}, "upgrade": True},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_delete_schema(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed delete_schema
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.delete_schema())

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(await futu_await(client.mgmt.authz.delete_schema()))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_schema_delete}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json=None,
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_load_schema(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed load_schema
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.load_schema())

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.return_value.json.return_value = {"schema": {"name": "test"}}
            self.assertIsNotNone(await futu_await(client.mgmt.authz.load_schema()))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_schema_load}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json=None,
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_save_namespace(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed save_namespace
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.save_namespace({}))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(
                await futu_await(
                    client.mgmt.authz.save_namespace({"name": "kuku"}, "old", "v1")
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_ns_save}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "namespace": {"name": "kuku"},
                    "oldName": "old",
                    "schemaName": "v1",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_delete_namespace(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed delete_namespace
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.delete_namespace("a"))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(
                await futu_await(client.mgmt.authz.delete_namespace("a", "b"))
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_ns_delete}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"name": "a", "schemaName": "b"},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_save_relation_definition(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed save_relation_definition
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.save_relation_definition({}, "a"))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(
                await futu_await(
                    client.mgmt.authz.save_relation_definition(
                        {"name": "kuku"}, "a", "old", "v1"
                    )
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_rd_save}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "relationDefinition": {"name": "kuku"},
                    "namespace": "a",
                    "oldName": "old",
                    "schemaName": "v1",
                },
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_delete_relation_definition(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed delete_relation_definition
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.delete_relation_definition("a", "b"))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(
                await futu_await(
                    client.mgmt.authz.delete_relation_definition("a", "b", "c")
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_rd_delete}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"name": "a", "namespace": "b", "schemaName": "c"},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_create_relations(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed create_relations
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.create_relations([]))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(
                await futu_await(
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
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_create}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_delete_relations(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed delete_relations
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.delete_relations([]))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(
                await futu_await(
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
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_delete}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_delete_relations_for_resources(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed delete_relations_for_resources
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.delete_relations_for_resources([]))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            self.assertIsNone(
                await futu_await(
                    client.mgmt.authz.delete_relations_for_resources(["r"])
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_delete_resources}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"resources": ["r"]},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_has_relations(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed has_relations
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.has_relations([]))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.return_value.json.return_value = {
                "relationQueries": [{"hasRelation": True}]
            }
            self.assertIsNotNone(
                await futu_await(
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
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_has_relations}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_who_can_access(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed who_can_access
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.who_can_access("a", "b", "c"))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.return_value.json.return_value = {"targets": ["user1", "user2"]}
            self.assertIsNotNone(
                await futu_await(client.mgmt.authz.who_can_access("a", "b", "c"))
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_who}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"resource": "a", "relationDefinition": "b", "namespace": "c"},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_resource_relations(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed resource_relations
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.resource_relations("a"))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.return_value.json.return_value = {
                "relations": [{"resource": "a", "target": "b"}]
            }
            self.assertIsNotNone(
                await futu_await(client.mgmt.authz.resource_relations("a"))
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_resource}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"resource": "a"},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_targets_relations(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed targets_relations
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.targets_relations(["a"]))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.return_value.json.return_value = {
                "relations": [{"target": "a", "resource": "b"}]
            }
            self.assertIsNotNone(
                await futu_await(client.mgmt.authz.targets_relations(["a"]))
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_targets}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"targets": ["a"]},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_what_can_target_access(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed what_can_target_access
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.what_can_target_access("a"))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.return_value.json.return_value = {
                "relations": [{"target": "a", "resource": "b"}]
            }
            self.assertIsNotNone(
                await futu_await(client.mgmt.authz.what_can_target_access("a"))
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_target_all}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"target": "a"},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_what_can_target_access_with_relation(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed what_can_target_access_with_relation
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    client.mgmt.authz.what_can_target_access_with_relation(
                        "a",
                        "b",
                        "c",
                    )
                )

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.return_value.json.return_value = {
                "relations": [{"target": "a", "resource": "b"}]
            }
            self.assertIsNotNone(
                await futu_await(
                    client.mgmt.authz.what_can_target_access_with_relation(
                        "a", "b", "c"
                    )
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_re_target_with_relation}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"target": "a", "relationDefinition": "b", "namespace": "c"},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_get_modified(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )

        # Test failed get_modified
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(client.mgmt.authz.get_modified())

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.return_value.json.return_value = {
                "relations": {"resources": ["r1"], "targets": ["t1"]}
            }
            self.assertIsNotNone(await futu_await(client.mgmt.authz.get_modified()))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.authz_get_modified}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"since": 0},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
