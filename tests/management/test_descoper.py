import pytest

from descope import (
    AuthException,
    DescoperAttributes,
    DescoperCreate,
    DescoperProjectRole,
    DescoperRBAC,
    DescoperRole,
    DescoperTagRole,
)
from descope.management.common import MgmtV1

from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.testutils import PUBLIC_KEY_DICT


@pytest.mark.asyncio
class TestDescoper:
    async def test_create(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_put(make_response(status=400)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.descoper.create(
                        [
                            DescoperCreate(
                                login_id="user1@example.com",
                            )
                        ]
                    )
                )

        # Test empty descopers
        with pytest.raises(ValueError):
            await client.invoke(client.mgmt.descoper.create([]))

        # Test success flow
        with client.mock_mgmt_put(
            make_response(
                {
                    "descopers": [
                        {
                            "id": "U2111111111111111111111111",
                            "attributes": {
                                "displayName": "Test User 2",
                                "email": "user2@example.com",
                                "phone": "+123456",
                            },
                            "rbac": {
                                "isCompanyAdmin": False,
                                "tags": [],
                                "projects": [
                                    {
                                        "projectIds": ["P2111111111111111111111111"],
                                        "role": "admin",
                                    }
                                ],
                            },
                            "status": "invited",
                        }
                    ],
                    "total": 1,
                }
            )
        ) as mock_put:
            resp = await client.invoke(
                client.mgmt.descoper.create(
                    descopers=[
                        DescoperCreate(
                            login_id="user1@example.com",
                            attributes=DescoperAttributes(
                                display_name="Test User 2",
                                phone="+123456",
                                email="user2@example.com",
                            ),
                            rbac=DescoperRBAC(
                                projects=[
                                    DescoperProjectRole(
                                        project_ids=["P2111111111111111111111111"],
                                        role=DescoperRole.ADMIN,
                                    )
                                ],
                            ),
                        )
                    ],
                )
            )
            descopers = resp["descopers"]
            assert len(descopers) == 1
            assert descopers[0]["id"] == "U2111111111111111111111111"
            assert resp["total"] == 1
            assert_http_called(
                mock_put,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.descoper_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "descopers": [
                        {
                            "loginId": "user1@example.com",
                            "attributes": {
                                "displayName": "Test User 2",
                                "email": "user2@example.com",
                                "phone": "+123456",
                            },
                            "sendInvite": False,
                            "rbac": {
                                "isCompanyAdmin": False,
                                "tags": [],
                                "projects": [
                                    {
                                        "projectIds": ["P2111111111111111111111111"],
                                        "role": "admin",
                                    }
                                ],
                            },
                        }
                    ]
                },
                follow_redirects=False,
            )

    async def test_create_with_tag_roles(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test success flow with tag roles
        with client.mock_mgmt_put(
            make_response(
                {
                    "descopers": [
                        {
                            "id": "U2111111111111111111111111",
                            "attributes": {
                                "displayName": "Test User",
                                "email": "user@example.com",
                                "phone": "",
                            },
                            "rbac": {
                                "isCompanyAdmin": False,
                                "tags": [{"tags": ["tag1", "tag2"], "role": "auditor"}],
                                "projects": [],
                            },
                            "status": "invited",
                        }
                    ],
                    "total": 1,
                }
            )
        ) as mock_put:
            resp = await client.invoke(
                client.mgmt.descoper.create(
                    descopers=[
                        DescoperCreate(
                            login_id="user@example.com",
                            rbac=DescoperRBAC(
                                tags=[
                                    DescoperTagRole(
                                        tags=["tag1", "tag2"],
                                        role=DescoperRole.AUDITOR,
                                    )
                                ],
                            ),
                        )
                    ],
                )
            )
            descopers = resp["descopers"]
            assert len(descopers) == 1
            assert len(descopers[0]["rbac"]["tags"]) == 1
            assert descopers[0]["rbac"]["tags"][0]["tags"] == ["tag1", "tag2"]
            assert_http_called(
                mock_put,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.descoper_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "descopers": [
                        {
                            "loginId": "user@example.com",
                            "attributes": None,
                            "sendInvite": False,
                            "rbac": {
                                "isCompanyAdmin": False,
                                "tags": [{"tags": ["tag1", "tag2"], "role": "auditor"}],
                                "projects": [],
                            },
                        }
                    ]
                },
                follow_redirects=False,
            )

    async def test_load(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=400)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.descoper.load("descoper-id"))

        # Test empty id
        with pytest.raises(ValueError):
            await client.invoke(client.mgmt.descoper.load(""))

        # Test success flow
        with client.mock_mgmt_get(
            make_response(
                {
                    "descoper": {
                        "id": "U2222222222222222222222222",
                        "attributes": {
                            "displayName": "Test User 2",
                            "email": "user2@example.com",
                            "phone": "+123456",
                        },
                        "rbac": {
                            "isCompanyAdmin": False,
                            "tags": [],
                            "projects": [
                                {
                                    "projectIds": ["P2111111111111111111111111"],
                                    "role": "admin",
                                }
                            ],
                        },
                        "status": "invited",
                    }
                }
            )
        ) as mock_get:
            resp = await client.invoke(client.mgmt.descoper.load("U2222222222222222222222222"))
            descoper = resp["descoper"]
            assert descoper["id"] == "U2222222222222222222222222"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.descoper_load_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={"id": "U2222222222222222222222222"},
                follow_redirects=True,
            )

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_patch(make_response(status=400)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.descoper.update(
                        "descoper-id",
                        None,
                        DescoperRBAC(is_company_admin=True),
                    )
                )

        # Test empty id
        with pytest.raises(ValueError):
            await client.invoke(client.mgmt.descoper.update(""))

        # Test success flow
        with client.mock_mgmt_patch(
            make_response(
                {
                    "descoper": {
                        "id": "U2333333333333333333333333",
                        "attributes": {
                            "displayName": "Updated User",
                            "email": "user4@example.com",
                            "phone": "+1234358730",
                        },
                        "rbac": {
                            "isCompanyAdmin": True,
                            "tags": [],
                            "projects": [],
                        },
                        "status": "invited",
                    }
                }
            )
        ) as mock_patch:
            resp = await client.invoke(
                client.mgmt.descoper.update(
                    "U2333333333333333333333333",
                    DescoperAttributes("Updated User", "user4@example.com", "+1234358730"),
                    DescoperRBAC(is_company_admin=True),
                )
            )
            descoper = resp["descoper"]
            assert descoper["id"] == "U2333333333333333333333333"
            assert descoper["rbac"]["isCompanyAdmin"] is True
            assert_http_called(
                mock_patch,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.descoper_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "id": "U2333333333333333333333333",
                    "rbac": {
                        "isCompanyAdmin": True,
                        "tags": [],
                        "projects": [],
                    },
                    "attributes": {
                        "displayName": "Updated User",
                        "email": "user4@example.com",
                        "phone": "+1234358730",
                    },
                },
                follow_redirects=False,
            )

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_delete(make_response(status=400)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.descoper.delete("descoper-id"))

        # Test empty id
        with pytest.raises(ValueError):
            await client.invoke(client.mgmt.descoper.delete(""))

        # Test success flow
        with client.mock_mgmt_delete(make_response()) as mock_delete:
            assert await client.invoke(client.mgmt.descoper.delete("U2111111111111111111111111")) is None
            assert_http_called(
                mock_delete,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.descoper_delete_path}",
                params={"id": "U2111111111111111111111111"},
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                follow_redirects=False,
            )

    async def test_list(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=400)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.descoper.list())

        # Test success flow
        with client.mock_mgmt_post(
            make_response(
                {
                    "descopers": [
                        {
                            "id": "U2444444444444444444444444",
                            "attributes": {
                                "displayName": "Admin User",
                                "email": "admin@example.com",
                                "phone": "",
                            },
                            "rbac": {
                                "isCompanyAdmin": True,
                                "tags": [],
                                "projects": [],
                            },
                            "status": "enabled",
                        },
                        {
                            "id": "U2555555555555555555555555",
                            "attributes": {
                                "displayName": "Another User",
                                "email": "user3@example.com",
                                "phone": "+123456",
                            },
                            "rbac": {
                                "isCompanyAdmin": False,
                                "tags": [],
                                "projects": [],
                            },
                            "status": "invited",
                        },
                        {
                            "id": "U2666666666666666666666666",
                            "attributes": {
                                "displayName": "Test User 1",
                                "email": "user2@example.com",
                                "phone": "+123456",
                            },
                            "rbac": {
                                "isCompanyAdmin": False,
                                "tags": [],
                                "projects": [
                                    {
                                        "projectIds": ["P2222222222222222222222222"],
                                        "role": "admin",
                                    }
                                ],
                            },
                            "status": "invited",
                        },
                    ],
                    "total": 3,
                }
            )
        ) as mock_post:
            resp = await client.invoke(client.mgmt.descoper.list())
            descopers = resp["descopers"]
            assert len(descopers) == 3
            assert resp["total"] == 3

            # First descoper - company admin
            assert descopers[0]["id"] == "U2444444444444444444444444"
            assert descopers[0]["attributes"]["displayName"] == "Admin User"
            assert descopers[0]["rbac"]["isCompanyAdmin"] is True
            assert descopers[0]["status"] == "enabled"

            # Second descoper
            assert descopers[1]["id"] == "U2555555555555555555555555"
            assert descopers[1]["rbac"]["isCompanyAdmin"] is False

            # Third descoper - with project role
            assert descopers[2]["id"] == "U2666666666666666666666666"
            assert len(descopers[2]["rbac"]["projects"]) == 1

            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.descoper_list_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={},
                follow_redirects=False,
            )
