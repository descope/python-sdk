from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL
from tests.conftest import PROJECT_ID, make_response
from tests.testutils import PUBLIC_KEY_DICT


@pytest.mark.parametrize(
    "since,expected_utc",
    [
        (None, None),
        (datetime(2026, 1, 15, 12, 30, 45, 123000), datetime(2026, 1, 15, 12, 30, 45, 123000, tzinfo=timezone.utc)),
        (datetime(2026, 1, 15, 12, tzinfo=timezone.utc), datetime(2026, 1, 15, 12, tzinfo=timezone.utc)),
        (
            datetime(2026, 1, 15, 12, tzinfo=timezone(timedelta(hours=5, minutes=30))),
            datetime(2026, 1, 15, 6, 30, tzinfo=timezone.utc),
        ),
        (
            datetime(2026, 1, 15, 12, tzinfo=ZoneInfo("America/Los_Angeles")),
            datetime(2026, 1, 15, 20, tzinfo=timezone.utc),
        ),
        (
            datetime(2026, 7, 15, 12, tzinfo=ZoneInfo("America/Los_Angeles")),
            datetime(2026, 7, 15, 19, tzinfo=timezone.utc),
        ),
        (
            datetime(2026, 11, 1, 1, 30, tzinfo=ZoneInfo("America/Los_Angeles"), fold=0),
            datetime(2026, 11, 1, 8, 30, tzinfo=timezone.utc),
        ),
        (
            datetime(2026, 11, 1, 1, 30, tzinfo=ZoneInfo("America/Los_Angeles"), fold=1),
            datetime(2026, 11, 1, 9, 30, tzinfo=timezone.utc),
        ),
    ],
    ids=[
        "omitted",
        "naive-utc-with-milliseconds",
        "utc",
        "positive-offset",
        "pacific-winter",
        "pacific-summer",
        "dst-first-fold",
        "dst-second-fold",
    ],
)
async def test_get_modified_preserves_since_instant(client_factory, since, expected_utc):
    client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
    relations = {"resources": ["resource"], "targets": ["target"], "schemaChanged": False}
    with client.mock_mgmt_post(make_response({"relations": relations})) as request:
        result = await client.invoke(client.mgmt.authz.get_modified(since))
    assert result == relations
    assert request.call_args.args[0] == f"{DEFAULT_BASE_URL}{MgmtV1.authz_get_modified}"
    assert request.call_args.kwargs["json"] == {
        "since": int(expected_utc.timestamp() * 1000) if expected_utc is not None else 0
    }
