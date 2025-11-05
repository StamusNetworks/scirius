import pytest
import secrets

from datetime import UTC, datetime

from django.conf import settings
from django.contrib.auth.models import User
from unittest.mock import MagicMock


# Mock the required dependencies that are imported in models.py
@pytest.fixture
def mock_suricata_dependencies(mocker):
    """Mocks external modules and task classes for CeleryTask logic."""
    settings.RULESET_MIDDLEWARE = "suricata"

    # Mock the tasks module used by CeleryTask
    mock_tasks = MagicMock()
    mock_tasks.SciriusTask = type("SciriusTask", (object,), {})  # Base class

    # Mock a concrete task class
    MockConcreteTask = type(
        "MockConcreteTask",
        (mock_tasks.SciriusTask,),
        {
            "HIDDEN": False,
            "SHOW_IN_PENDING": False,
            "display": lambda self: {"title": "Mock Task Title", "extra": 1},
            "run": lambda self: None,
        },
    )

    # Mock a hidden task class
    MockHiddenTask = type(
        "MockHiddenTask",
        (mock_tasks.SciriusTask,),
        {
            "HIDDEN": True,
            "SHOW_IN_PENDING": False,
            "display": lambda self: {"title": "Hidden Task Title", "extra": 1},
            "run": lambda self: None,
        },
    )

    mock_tasks.run_celery_task = MagicMock()
    mock_tasks.get_tasks = MagicMock(return_value=["MockConcreteTask", "MockHiddenTask"])

    mocker.patch("suricata.models.tasks", mock_tasks)

    # Expose the mocked task classes for models.py to resolve them
    mock_tasks.MockConcreteTask = MockConcreteTask
    mock_tasks.MockHiddenTask = MockHiddenTask


@pytest.fixture
def mock_user(db):
    """Creates a basic Django User."""
    user = User.objects.create_user(username=f"testuser_{secrets.token_hex(8)}")
    yield user
    # user.delete()


@pytest.fixture
def mock_ruleset(db):
    """Creates a mock Ruleset object for Suricata."""
    from rules.models.model import Ruleset

    ruleset = Ruleset.objects.create(
        name="test_ruleset_{secrets.token_hex(8)}",
        created_date=datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC),
        updated_date=datetime(2025, 1, 1, 10, 10, 0, tzinfo=UTC),
    )
    yield ruleset
    ruleset.delete()


@pytest.fixture
def suricata_instance(db, mock_ruleset):
    """Creates a Suricata model instance."""
    from suricata.models import Suricata

    suri = Suricata.objects.create(
        name="mock-probe",
        descr="Test probe",
        ruleset=mock_ruleset,
        created_date=datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC),
        updated_date=datetime(2025, 1, 1, 10, 10, 0, tzinfo=UTC),
    )
    yield suri
    suri.delete()
