import json
import unittest
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient


class TestTenant(unittest.TestCase):
    def setUp(self) -> None:
        self.dummy_project_id = "dummy"
        self.public_key_dict = {
            "alg": "ES384",
            "crv": "P-384",
            "kid": "P2CtzUhdqpIF2ys9gg7ms06UvtC4",
            "kty": "EC",
            "use": "sig",
            "x": "pX1l7nT2turcK5_Cdzos8SKIhpLh1Wy9jmKAVyMFiOCURoj-WQX1J0OUQqMsQO0s",
            "y": "B0_nWAv2pmG_PzoH3-bSYZZzLNKUA0RoE2SH7DaS0KV4rtfWZhYd0MEr0xfdGKx0",
        }

    def test_create(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.tenant.create,
                "valid-key",
                "valid-name",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"id": "t1"}""")
            mock_post.return_value = network_resp
            resp = client.mgmt.tenant.create("key", "name", "t1", ["domain.com"])
            self.assertEqual(resp["id"], "t1")

    def test_update(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.tenant.update,
                "valid-key",
                "valid-id",
                "valid-name",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.tenant.update("key", "t1", "new-name", ["domain.com"])
            )

    def test_delete(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict)

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.tenant.delete,
                "valid-key",
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.tenant.delete("key", "t1"))
