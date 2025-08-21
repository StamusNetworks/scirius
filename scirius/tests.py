import unittest
import datetime

from scirius.utils import convert_datetime_to_timestamp


class TestConvertDatetimeToTimestamp(unittest.TestCase):
    def test_conversion_in_seconds(self):
        dt = datetime.datetime(2025, 8, 26, 10, 16, 50, tzinfo=datetime.UTC)
        expected_timestamp = 1756209410
        self.assertEqual(convert_datetime_to_timestamp(dt), expected_timestamp)
        self.assertEqual(convert_datetime_to_timestamp(dt, False), expected_timestamp)

    def test_conversion_in_milliseconds(self):
        dt = datetime.datetime(2025, 8, 26, 10, 16, 50, tzinfo=datetime.UTC)
        expected_timestamp_ms = 1756209410000
        self.assertEqual(convert_datetime_to_timestamp(dt, True), expected_timestamp_ms)
