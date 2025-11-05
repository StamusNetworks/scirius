import datetime
import pytest

from pathlib import Path
from unittest.mock import MagicMock
from zoneinfo import ZoneInfo

from django.http import HttpRequest, QueryDict
from freezegun import freeze_time

from scirius.utils import (
    ExtendedJSONSerializer,
    build_path_info,
    convert_datetime_to_timestamp,
    get_folder_size,
    is_ajax,
    merge_dict_deeply,
    read_in_chunks,
    sizeof_fmt,
)


@pytest.fixture
def authenticated_request(mocker):
    """Returns a mocked authenticated HttpRequest object with necessary attributes."""
    request = MagicMock(spec=HttpRequest)
    request.user = MagicMock(is_authenticated=True, has_perm=mocker.MagicMock(return_value=True))
    request.user.sciriususer = mocker.MagicMock(timezone="Europe/Paris")
    request.path_info = "/"
    request.path = "/"
    request.GET = QueryDict()
    request.session = {"duration": "24"}
    request.resolver_match = mocker.MagicMock(view_name="home")
    return request


@pytest.fixture
def unauthenticated_request(mocker):
    """Returns a mocked unauthenticated HttpRequest object."""
    request = mocker.MagicMock(spec=HttpRequest)
    request.user = mocker.MagicMock(is_authenticated=False)
    request.path_info = "/"
    request.path = "/"
    return request


@pytest.mark.parametrize(
    "path_info, expected",
    [
        ("/rules/pk/edit/", "edit"),
        ("/rules/settings/user/pk/1/", "settings - user - 1"),
        ("/rules/view/all", "view - all"),
        ("/", ""),
        (" / ", ""),
        ("/api/v1/data/", "api - v1 - data"),
        ("/rules/", "home"),
    ],
)
def test_build_path_info(path_info: str, expected: str):
    """Test path info cleaning and formatting."""
    request = MagicMock(path_info=path_info)
    assert build_path_info(request) == expected


# --- other tests ---


@pytest.mark.parametrize(
    "header_value, expected",
    [
        ("XMLHttpRequest", True),
        (None, False),
        ("some-other-value", False),
    ],
)
def test_is_ajax(header_value, expected):
    """Test is_ajax returns True only when the specific header value is present."""
    headers = {"x-requested-with": header_value} if header_value else {}
    request = MagicMock(headers=headers)
    assert is_ajax(request) is expected


def test_get_folder_size(tmp_path: Path):
    """Test calculation of total file size recursively in a directory."""
    # Create files
    file1 = tmp_path / "file1.txt"
    file2 = tmp_path / "subdir/file2.bin"
    Path(tmp_path / "subdir").mkdir()

    file1.write_bytes(b"A" * 100)
    file2.write_bytes(b"B" * 200)

    assert get_folder_size(tmp_path) > 300  # because it is the size on disk not size of the content


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


def test_merge_dict_deeply_nested_overwrite():
    """Test deep merging of nested dictionaries, with overwrite of scalar values."""
    dest = {"a": 1, "b": {"c": 2, "d": 3}}
    src = {"b": {"d": 4, "e": 5}, "f": 6}
    expected = {"a": 1, "b": {"c": 2, "d": 4, "e": 5}, "f": 6}
    result = merge_dict_deeply(src, dest)
    assert result == expected


def test_merge_dict_deeply_src_overwrites_dest_scalar():
    """Test when source value is non-dict, it overwrites destination non-dict value."""
    dest = {"key": 1}
    src = {"key": 2}
    result = merge_dict_deeply(src, dest)
    assert result == {"key": 2}


def test_read_in_chunks():
    """Test reading a file in specified chunk sizes, including the final empty read."""
    data = b"0123456789abcdef"
    mock_file = MagicMock()
    # Sequence of reads: 5 bytes, 5 bytes, remaining (6 bytes), EOF (empty)
    mock_file.read.side_effect = [data[:5], data[5:10], data[10:], b""]

    chunks = list(read_in_chunks(mock_file, chunk_size=5))

    assert chunks == [b"01234", b"56789", b"abcdef"]
    assert mock_file.read.call_count == 4


@pytest.mark.parametrize(
    "num, expected",
    [
        (1, "1.0 B"),
        (1023, "1023.0 B"),
        (1024, "1.0 KB"),
        (1024**3 * 1.1, "1.1 GB"),
        (1024**8, "1.0 YB"),
        (1024**9 + 500, "1024.0 YB"),  # Tests the final fallback return for extremely large numbers
    ],
)
def test_sizeof_fmt(num: int, expected: str):
    """Test human-readable byte conversion across different units."""
    assert sizeof_fmt(num) == expected


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
