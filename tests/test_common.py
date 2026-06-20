from enum import Enum

from descope.common import (
    DeliveryMethod,
    LoginOptions,
    SignUpOptions,
    get_method_string,
    signup_options_to_dict,
)
from descope.exceptions import AuthException
from tests import common


class TestCommon(common.DescopeTest):
    def test_get_method_string(self):
        self.assertEqual(
            get_method_string(DeliveryMethod.EMAIL),
            "email",
        )
        self.assertEqual(
            get_method_string(DeliveryMethod.SMS),
            "sms",
        )
        self.assertEqual(
            get_method_string(DeliveryMethod.VOICE),
            "voice",
        )
        self.assertEqual(
            get_method_string(DeliveryMethod.WHATSAPP),
            "whatsapp",
        )
        self.assertEqual(
            get_method_string(DeliveryMethod.EMBEDDED),
            "Embedded",
        )

        class AAA(Enum):
            DUMMY = 4

        self.assertRaises(AuthException, get_method_string, AAA.DUMMY)

    def test_login_options_optional_fields(self):
        opts = LoginOptions(
            revoke_other_sessions=True,
            template_options={"key": "v"},
            template_id="tpl-1",
            locale="en",
        )
        self.assertTrue(opts.revokeOtherSessions)
        self.assertEqual(opts.templateOptions, {"key": "v"})
        self.assertEqual(opts.templateId, "tpl-1")
        self.assertEqual(opts.locale, "en")

    def test_signup_options_to_dict_empty(self):
        # None and a fully-empty SignUpOptions both yield {}
        self.assertEqual(signup_options_to_dict(None), {})
        self.assertEqual(signup_options_to_dict(SignUpOptions()), {})

    def test_signup_options_to_dict_full(self):
        opts = SignUpOptions(
            revoke_other_sessions=True,
            custom_claims={"role": "admin"},
            template_options={"key": "v"},
            template_id="tpl-2",
        )
        result = signup_options_to_dict(opts)
        self.assertEqual(result["revokeOtherSessions"], True)
        self.assertEqual(result["customClaims"], {"role": "admin"})
        self.assertEqual(result["templateOptions"], {"key": "v"})
        self.assertEqual(result["templateId"], "tpl-2")
