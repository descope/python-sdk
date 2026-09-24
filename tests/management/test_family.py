import pytest

from descope import AuthException, CustomAttribute, CustomAttributeOption
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT

MGMT_HEADERS = {
    **default_headers,
    "Authorization": f"Bearer {PROJECT_ID}:key",
    "x-descope-project-id": PROJECT_ID,
}

FAMILY = {
    "id": "f1",
    "name": "Demo Family",
    "customAttributes": {"plan": "free"},
    "disabled": False,
    "photo": "https://example.com/photo.png",
    "createdTime": 1700000000,
}


def assert_post(mock_post, mode, path, json):
    assert_http_called(
        mock_post,
        mode,
        f"{DEFAULT_BASE_URL}{path}",
        headers=MGMT_HEADERS,
        params=None,
        json=json,
        follow_redirects=False,
    )


def assert_get(mock_get, mode, path):
    assert_http_called(
        mock_get,
        mode,
        f"{DEFAULT_BASE_URL}{path}",
        headers=MGMT_HEADERS,
        params=None,
        follow_redirects=True,
    )


class TestFamily:
    async def test_create(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.create("Demo Family"))

        # Test success flow, only the name
        with client.mock_mgmt_post(make_response({"family": FAMILY})) as mock_post:
            resp = await client.invoke(client.mgmt.family.create("Demo Family"))
            assert resp["family"] == FAMILY
            assert_post(mock_post, client.mode, MgmtV1.family_create_path, {"name": "Demo Family"})

        # Test success flow, all fields
        with client.mock_mgmt_post(make_response({"family": FAMILY})) as mock_post:
            resp = await client.invoke(
                client.mgmt.family.create(
                    "Demo Family",
                    custom_attributes={"plan": "free"},
                    photo="https://example.com/photo.png",
                    disabled=False,
                    family_id="f1",
                )
            )
            assert resp["family"]["id"] == "f1"
            assert_post(
                mock_post,
                client.mode,
                MgmtV1.family_create_path,
                {
                    "name": "Demo Family",
                    "customAttributes": {"plan": "free"},
                    "photo": "https://example.com/photo.png",
                    "disabled": False,
                    "familyId": "f1",
                },
            )

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.update("f1", "New Name"))

        # Test success flow, omitted fields are not sent
        with client.mock_mgmt_post(make_response({"family": FAMILY})) as mock_post:
            resp = await client.invoke(client.mgmt.family.update("f1", disabled=True))
            assert resp["family"] == FAMILY
            assert_post(mock_post, client.mode, MgmtV1.family_update_path, {"id": "f1", "disabled": True})

        # Test success flow, all fields
        with client.mock_mgmt_post(make_response({"family": FAMILY})) as mock_post:
            await client.invoke(
                client.mgmt.family.update(
                    "f1",
                    name="New Name",
                    custom_attributes={"plan": "premium"},
                    photo="https://example.com/new.png",
                    disabled=False,
                )
            )
            assert_post(
                mock_post,
                client.mode,
                MgmtV1.family_update_path,
                {
                    "id": "f1",
                    "name": "New Name",
                    "customAttributes": {"plan": "premium"},
                    "photo": "https://example.com/new.png",
                    "disabled": False,
                },
            )

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.delete("f1"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            resp = await client.invoke(client.mgmt.family.delete("f1"))
            assert resp is None
            assert_post(mock_post, client.mode, MgmtV1.family_delete_path, {"id": "f1"})

    async def test_search(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.search())

        # Test success flow, no filters returns all families
        with client.mock_mgmt_post(make_response({"families": [FAMILY]})) as mock_post:
            resp = await client.invoke(client.mgmt.family.search())
            assert resp["families"] == [FAMILY]
            assert_post(mock_post, client.mode, MgmtV1.family_search_path, {})

        # Test success flow, all filters
        with client.mock_mgmt_post(make_response({"families": [FAMILY]})) as mock_post:
            await client.invoke(
                client.mgmt.family.search(
                    family_ids=["f1"],
                    free_text="demo",
                    family_names=["Demo Family"],
                    page=0,
                    size=10,
                    custom_attributes={"plan": "free"},
                )
            )
            assert_post(
                mock_post,
                client.mode,
                MgmtV1.family_search_path,
                {
                    "familyIds": ["f1"],
                    "freeText": "demo",
                    "familyNames": ["Demo Family"],
                    "page": 0,
                    "size": 10,
                    "customAttributes": {"plan": "free"},
                },
            )

    async def test_create_dependent(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.create_dependent("f1", name="Demo Kid"))

        # Test success flow, only the family
        user = {"userId": "u1", "loginIds": ["demo-kid"], "dependent": True}
        with client.mock_mgmt_post(make_response({"user": user})) as mock_post:
            resp = await client.invoke(client.mgmt.family.create_dependent("f1"))
            assert resp["user"] == user
            assert_post(mock_post, client.mode, MgmtV1.family_dependent_create_path, {"familyId": "f1"})

        # Test success flow, all fields
        with client.mock_mgmt_post(make_response({"user": user})) as mock_post:
            await client.invoke(
                client.mgmt.family.create_dependent(
                    "f1",
                    login_id="demo-kid",
                    name="Demo Kid",
                    email="guardian@example.com",
                    phone="+15555550100",
                    given_name="Demo",
                    middle_name="M",
                    family_name="Kid",
                    picture="https://example.com/kid.png",
                    custom_attributes={"ak": "av"},
                    family_scoped_attributes={"f1": {"nickname": "Kiddo"}},
                )
            )
            assert_post(
                mock_post,
                client.mode,
                MgmtV1.family_dependent_create_path,
                {
                    "familyId": "f1",
                    "loginId": "demo-kid",
                    "name": "Demo Kid",
                    "email": "guardian@example.com",
                    "phone": "+15555550100",
                    "givenName": "Demo",
                    "middleName": "M",
                    "familyName": "Kid",
                    "picture": "https://example.com/kid.png",
                    "customAttributes": {"ak": "av"},
                    "familyScopedAttributes": {"f1": {"nickname": "Kiddo"}},
                },
            )

    async def test_delete_dependent(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.delete_dependent("u1"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            resp = await client.invoke(client.mgmt.family.delete_dependent("u1"))
            assert resp is None
            assert_post(mock_post, client.mode, MgmtV1.family_dependent_delete_path, {"userId": "u1"})

    async def test_impersonate_dependent(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.impersonate_dependent("guardian", "demo-kid"))

        # Test success flow, no selected family
        with client.mock_mgmt_post(make_response({"jwt": "imp-jwt"})) as mock_post:
            jwt = await client.invoke(client.mgmt.family.impersonate_dependent("guardian", "demo-kid"))
            assert jwt == "imp-jwt"
            assert_post(
                mock_post,
                client.mode,
                MgmtV1.family_impersonate_path,
                {"impersonatorUserIdOrLoginId": "guardian", "dependentLoginId": "demo-kid"},
            )

        # Test success flow, with selected family
        with client.mock_mgmt_post(make_response({"jwt": "imp-jwt"})) as mock_post:
            jwt = await client.invoke(client.mgmt.family.impersonate_dependent("guardian", "demo-kid", "f1"))
            assert jwt == "imp-jwt"
            assert_post(
                mock_post,
                client.mode,
                MgmtV1.family_impersonate_path,
                {
                    "impersonatorUserIdOrLoginId": "guardian",
                    "dependentLoginId": "demo-kid",
                    "selectedFamily": "f1",
                },
            )

    async def test_stop_impersonation(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.stop_impersonation("imp-jwt"))

        # Test success flow, only the jwt
        with client.mock_mgmt_post(make_response({"jwt": "own-jwt"})) as mock_post:
            jwt = await client.invoke(client.mgmt.family.stop_impersonation("imp-jwt"))
            assert jwt == "own-jwt"
            assert_post(mock_post, client.mode, MgmtV1.family_stop_impersonation_path, {"jwt": "imp-jwt"})

        # Test success flow, all fields
        with client.mock_mgmt_post(make_response({"jwt": "own-jwt"})) as mock_post:
            jwt = await client.invoke(
                client.mgmt.family.stop_impersonation("imp-jwt", custom_claims={"k1": "v1"}, refresh_duration=300)
            )
            assert jwt == "own-jwt"
            assert_post(
                mock_post,
                client.mode,
                MgmtV1.family_stop_impersonation_path,
                {"jwt": "imp-jwt", "customClaims": {"k1": "v1"}, "refreshDuration": 300},
            )

    async def test_load_settings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_get(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.load_settings())

        # Test success flow
        settings = {"enabled": True, "maxFamilyMembers": 6, "allowMultipleFamiliesUsers": False}
        with client.mock_mgmt_get(make_response(settings)) as mock_get:
            resp = await client.invoke(client.mgmt.family.load_settings())
            assert resp == settings
            assert_get(mock_get, client.mode, MgmtV1.family_settings_path)

    async def test_update_settings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.update_settings(enabled=True))

        settings = {"enabled": True, "maxFamilyMembers": 6, "allowMultipleFamiliesUsers": True}

        # Test success flow, partial update
        with client.mock_mgmt_post(make_response(settings)) as mock_post:
            resp = await client.invoke(client.mgmt.family.update_settings(enabled=True))
            assert resp == settings
            assert_post(mock_post, client.mode, MgmtV1.family_settings_path, {"enabled": True})

        # Test success flow, all fields
        with client.mock_mgmt_post(make_response(settings)) as mock_post:
            await client.invoke(
                client.mgmt.family.update_settings(
                    enabled=True, max_family_members=6, allow_multiple_families_users=True
                )
            )
            assert_post(mock_post, client.mode, MgmtV1.family_settings_path, settings)

    async def test_load_custom_attributes(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_get(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.load_custom_attributes())

        # Test success flow
        data = {"data": [{"name": "plan", "type": 1}]}
        with client.mock_mgmt_get(make_response(data)) as mock_get:
            resp = await client.invoke(client.mgmt.family.load_custom_attributes())
            assert resp == data
            assert_get(mock_get, client.mode, MgmtV1.family_load_custom_attributes_path)

    async def test_create_custom_attributes(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        attributes = [
            CustomAttribute("plan", 1, display_name="Plan"),
            CustomAttribute(
                "tier",
                4,
                display_name="Tier",
                options=[CustomAttributeOption("gold", "Gold"), CustomAttributeOption("silver", "Silver")],
                view_permissions=["view"],
                edit_permissions=["edit"],
            ),
        ]

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.create_custom_attributes(attributes))

        # Test success flow
        data = {"data": [{"name": "plan", "type": 1}, {"name": "tier", "type": 4}]}
        with client.mock_mgmt_post(make_response(data)) as mock_post:
            resp = await client.invoke(client.mgmt.family.create_custom_attributes(attributes))
            assert resp == data
            assert_post(
                mock_post,
                client.mode,
                MgmtV1.family_create_custom_attributes_path,
                {
                    "attributes": [
                        {"name": "plan", "type": 1, "displayName": "Plan"},
                        {
                            "name": "tier",
                            "type": 4,
                            "displayName": "Tier",
                            "options": [
                                {"value": "gold", "label": "Gold"},
                                {"value": "silver", "label": "Silver"},
                            ],
                            "viewPermissions": ["view"],
                            "editPermissions": ["edit"],
                        },
                    ]
                },
            )

    async def test_delete_custom_attributes(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.family.delete_custom_attributes(["plan"]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"data": []})) as mock_post:
            resp = await client.invoke(client.mgmt.family.delete_custom_attributes(["plan"]))
            assert resp == {"data": []}
            assert_post(
                mock_post,
                client.mode,
                MgmtV1.family_delete_custom_attributes_path,
                {"names": ["plan"]},
            )
