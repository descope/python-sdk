from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.future_utils import futu_await
from descope.management.common import MgmtV1

from tests.testutils import SSLMatcher, mock_http_call
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
                await futu_await(client.mgmt.fga.save_schema(""))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            result = await futu_await(client.mgmt.fga.save_schema("model AuthZ 1.0"))
            self.assertIsNone(result)
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_save_schema}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"dsl": "model AuthZ 1.0"},
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
                await futu_await(client.mgmt.fga.create_relations([]))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            result = await futu_await(
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
            self.assertIsNone(result)
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
                await futu_await(client.mgmt.fga.delete_relations([]))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            result = await futu_await(
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
            self.assertIsNone(result)
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
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_check(self):
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
                await futu_await(client.mgmt.fga.check([]))

        # Test success flow
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.return_value.json.return_value = {
                "tuples": [
                    {
                        "tuple": {
                            "resource": "r",
                            "resourceType": "rt",
                            "relation": "rel",
                            "target": "u",
                            "targetType": "ty",
                        },
                        "allowed": True,
                    }
                ]
            }
            result = await futu_await(
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
            self.assertIsNotNone(result)
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
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_load_resources_details_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )
        response_body = {
            "resourcesDetails": [
                {"resourceId": "r1", "resourceType": "type1", "displayName": "Name1"},
                {"resourceId": "r2", "resourceType": "type2", "displayName": "Name2"},
            ]
        }
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.return_value.json.return_value = response_body
            ids = [
                {"resourceId": "r1", "resourceType": "type1"},
                {"resourceId": "r2", "resourceType": "type2"},
            ]
            details = await futu_await(client.mgmt.fga.load_resources_details(ids))
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
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_load_resources_details_error(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            ids = [{"resourceId": "r1", "resourceType": "type1"}]
            with self.assertRaises(AuthException):
                await futu_await(
                    client.mgmt.fga.load_resources_details(
                        ids,
                    )
                )

    async def test_save_resources_details_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )
        details = [
            {"resourceId": "r1", "resourceType": "type1", "displayName": "Name1"}
        ]
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            result = await futu_await(client.mgmt.fga.save_resources_details(details))
            self.assertIsNone(result)
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_resources_save}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"resourcesDetails": details},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_save_resources_details_error(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
        )
        details = [
            {"resourceId": "r1", "resourceType": "type1", "displayName": "Name1"}
        ]
        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = False
            with self.assertRaises(AuthException):
                await futu_await(
                    client.mgmt.fga.save_resources_details(
                        details,
                    )
                )

    async def test_fga_cache_url_save_schema(self):
        # Test FGA cache URL functionality for save_schema
        fga_cache_url = "https://my-fga-cache.example.com"
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            fga_cache_url=fga_cache_url,
            async_mode=self.async_test,
        )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            await futu_await(client.mgmt.fga.save_schema("model AuthZ 1.0"))
            mock_post.assert_called_with(
                f"{fga_cache_url}{MgmtV1.fga_save_schema}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"dsl": "model AuthZ 1.0"},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_fga_cache_url_create_relations(self):
        # Test FGA cache URL functionality for create_relations
        fga_cache_url = "https://my-fga-cache.example.com"
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            fga_cache_url=fga_cache_url,
            async_mode=self.async_test,
        )

        relations = [
            {
                "resource": "r",
                "resourceType": "rt",
                "relation": "rel",
                "target": "u",
                "targetType": "ty",
            }
        ]

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            await futu_await(client.mgmt.fga.create_relations(relations))
            mock_post.assert_called_with(
                f"{fga_cache_url}{MgmtV1.fga_create_relations}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"tuples": relations},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_fga_cache_url_delete_relations(self):
        # Test FGA cache URL functionality for delete_relations
        fga_cache_url = "https://my-fga-cache.example.com"
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            fga_cache_url=fga_cache_url,
            async_mode=self.async_test,
        )

        relations = [
            {
                "resource": "r",
                "resourceType": "rt",
                "relation": "rel",
                "target": "u",
                "targetType": "ty",
            }
        ]

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            await futu_await(client.mgmt.fga.delete_relations(relations))
            mock_post.assert_called_with(
                f"{fga_cache_url}{MgmtV1.fga_delete_relations}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"tuples": relations},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    async def test_fga_cache_url_check(self):
        # Test FGA cache URL functionality for check
        fga_cache_url = "https://my-fga-cache.example.com"
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            fga_cache_url=fga_cache_url,
            async_mode=self.async_test,
        )

        relations = [
            {
                "resource": "r",
                "resourceType": "rt",
                "relation": "rel",
                "target": "u",
                "targetType": "ty",
            }
        ]

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            mock_post.return_value.json.return_value = {
                "tuples": [
                    {
                        "allowed": True,
                        "tuple": relations[0],
                    }
                ]
            }
            result = await futu_await(client.mgmt.fga.check(relations))
            mock_post.assert_called_with(
                f"{fga_cache_url}{MgmtV1.fga_check}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"tuples": relations},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
            self.assertEqual(len(result), 1)
            self.assertTrue(result[0]["allowed"])
            self.assertEqual(result[0]["relation"], relations[0])

    async def test_fga_without_cache_url_uses_default_base_url(self):
        # Test that FGA methods use default base URL when cache URL is not provided
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
            async_mode=self.async_test,
            # No fga_cache_url provided
        )

        with mock_http_call(self.async_test, "post") as mock_post:
            mock_post.return_value.is_success = True
            await futu_await(client.mgmt.fga.save_schema("model AuthZ 1.0"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.fga_save_schema}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"dsl": "model AuthZ 1.0"},
                follow_redirects=False,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
