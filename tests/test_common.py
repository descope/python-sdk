from enum import Enum

from descope.common import DeliveryMethod, get_method_string
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
