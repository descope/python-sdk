import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.management.common import MgmtV1

from .. import common


class TestUser(common.DescopeTest):
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

    def test_update_jwt(self):
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
                AuthException, client.mgmt.jwt.update_jwt, "jwt", {"k1": "v1"}
            )

            self.assertRaises(
                AuthException, client.mgmt.jwt.update_jwt, "", {"k1": "v1"}
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"jwt": "response"}""")
            mock_post.return_value = network_resp
            resp = client.mgmt.jwt.update_jwt("test", {"k1": "v1"})
            self.assertEqual(resp, "response")
            expected_uri = f"{common.DEFAULT_BASE_URL}{MgmtV1.update_jwt_path}"
            mock_post.assert_called_with(
                expected_uri,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                data=json.dumps({"jwt": "test", "customClaims": {"k1": "v1"}}),
                allow_redirects=False,
                verify=True,
                params=None,
            )
