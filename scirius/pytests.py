import datetime
import pytest

from zoneinfo import ZoneInfo

from freezegun import freeze_time

from scirius.utils import ExtendedJSONSerializer, convert_datetime_to_timestamp, merge_dict_deeply, sizeof_fmt


@freeze_time("2025-08-26 10:16:50 UTC")
def test_conversion_in_seconds():
    dt = datetime.datetime(2025, 8, 26, 10, 16, 50, tzinfo=datetime.UTC)
    expected_timestamp = 1756203410
    assert convert_datetime_to_timestamp(dt) == expected_timestamp
    assert convert_datetime_to_timestamp(dt, False) == expected_timestamp


@freeze_time("2025-08-26 10:16:50 UTC")
def test_conversion_in_milliseconds():
    dt = datetime.datetime(2025, 8, 26, 10, 16, 50, tzinfo=datetime.UTC)
    expected_timestamp_ms = 1756203410000
    assert convert_datetime_to_timestamp(dt, True) == expected_timestamp_ms


@pytest.mark.timeout(2)
def test_merge_dict_deeply():
    a = {"first": {"all_rows": {"pass": "dog", "number": "1"}}}
    b = {"first": {"all_rows": {"fail": "cat", "number": "5"}}}
    result = merge_dict_deeply(b, a)
    assert result == {"first": {"all_rows": {"pass": "dog", "fail": "cat", "number": "5"}}}


def test_sizeof_fmt():
    assert sizeof_fmt(1) == "1.0 B"
    assert sizeof_fmt(2000) == "2.0 KB"
    assert sizeof_fmt(1800000) == "1.7 MB"
    assert sizeof_fmt(1222333444) == "1.1 GB"


def test_extended_json_serializer():
    serializer = ExtendedJSONSerializer()

    dt = datetime.datetime(2025, 8, 26, 10, 16, 50, 123456, tzinfo=datetime.UTC)
    res = serializer.dumps({"dt": dt})
    assert res.decode() == '{"dt":"2025-08-26T10:16:50.123456"}'

    dt = datetime.datetime(2025, 8, 26, 10, 16, 50, 123456, tzinfo=ZoneInfo("Europe/Paris"))
    res = serializer.dumps([dt])
    assert res.decode() == '["2025-08-26T08:16:50.123456"]'

    res = serializer.dumps({"a": 1, "b": "string", "c": [1, 2, 3], "d": {"key": "val", "t": dt}})
    assert res.decode() == '{"a":1,"b":"string","c":[1,2,3],"d":{"key":"val","t":"2025-08-26T08:16:50.123456"}}'
