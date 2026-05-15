from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from .. import common
from ..testutils import SSLMatcher


class TestLicense(common.DescopeTest):
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

    def test_get_failure(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )
        with patch("httpx.get") as mock_get:
            mock_get.return_value.is_success = False
            self.assertRaises(AuthException, client.mgmt.license.get)

    def test_get_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )
        with patch("httpx.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.is_success = True
            network_resp.json.return_value = {"rateLimitTier": "tier4"}
            mock_get.return_value = network_resp

            resp = client.mgmt.license.get()
            self.assertEqual(resp, {"rateLimitTier": "tier4"})

            mock_get.assert_called_with(
                f"{client._mgmt_http_client.base_url}{MgmtV1.license_get_path}",
                headers=mock.ANY,
                params=None,
                follow_redirects=True,
                verify=SSLMatcher(),
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_header_injected_after_handshake(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )
        # Simulate a completed handshake by setting the cached tier directly.
        client._mgmt_http_client.rate_limit_tier = "tier2"
        headers = client._mgmt_http_client._get_default_headers()
        self.assertEqual(headers.get("x-descope-license"), "tier2")

    def test_header_absent_when_tier_not_cached(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )
        # Default state has no rate limit tier yet.
        client._mgmt_http_client.rate_limit_tier = None
        headers = client._mgmt_http_client._get_default_headers()
        self.assertNotIn("x-descope-license", headers)
