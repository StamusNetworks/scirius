from unittest.mock import MagicMock

from rules.repository.analytic import AnalyticRepository


def test_get_fields():
    connector = MagicMock()
    repo = AnalyticRepository(connector=connector)
    assert repo._get_fields(["a.key", "b.key"]) == [
        {"key": "a.key.keyword", "name": "a.key"},
        {"key": "b.key.keyword", "name": "b.key"},
    ]
    assert repo._get_fields(["a.key", "alert.severity"]) == [
        {"key": "a.key.keyword", "name": "a.key"},
        {"key": "alert.severity", "name": "alert.severity"},
    ]
