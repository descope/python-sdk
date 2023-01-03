import json
import unittest
from unittest.mock import patch

import common

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_BASE_URL
from descope.management.common import MgmtV1


class TestGroup(unittest.TestCase):
    def setUp(self) -> None:
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

    def test_load_all_groups(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.group.load_all_groups,
                "tenant_id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.group.load_all_groups("someTenantId"))
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.groupLoadAllPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "tenantId": "someTenantId",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_load_all_groups_for_members(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.group.load_all_groups_for_members,
                "tenant_id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(
                client.mgmt.group.load_all_groups_for_members(
                    "someTenantId", ["one", "two"], ["three", "four"]
                )
            )
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.groupLoadAllForMemberPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "tenantId": "someTenantId",
                        "identifiers": ["three", "four"],
                        "jwtSubjects": ["one", "two"],
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_load_all_group_members(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.group.load_all_group_members,
                "tenant_id",
                "group_id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(
                client.mgmt.group.load_all_group_members("someTenantId", "someGroupId")
            )
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.groupLoadAllGroupMembersPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "tenantId": "someTenantId",
                        "groupId": "someGroupId",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )
