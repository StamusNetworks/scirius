import pytest
import json

from datetime import datetime, timedelta
from unittest.mock import MagicMock

from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time


from suricata.models import validate_hostname, Suricata, get_probe_hostnames, CeleryTask, RecurrentTask

# --- Utility Function Tests ---


def test_validate_hostname_valid():
    """Test that a valid hostname passes validation."""
    validate_hostname("valid-hostname-1")
    # No exception raised means success


def test_validate_hostname_invalid():
    """Test that a hostname with a space raises ValidationError."""
    with pytest.raises(ValidationError):
        validate_hostname("invalid hostname")


# --- Suricata Model Tests ---


def test_suricata_str(suricata_instance):
    """Test the string representation of Suricata instance."""
    assert str(suricata_instance) == "mock-probe"


@freeze_time("2025-01-01 10:00:00")
def test_suricata_push_success(suricata_instance, settings, tmp_path):
    """Test Suricata.push() creates the reload file when one doesn't exist."""
    settings.SURICATA_OUTPUT_DIRECTORY = str(tmp_path)

    assert suricata_instance.push() is True

    reload_file = tmp_path / "scirius.reload"
    assert reload_file.exists()
    assert reload_file.read_text() == "2025-01-01 10:00:00+00:00"


def test_suricata_push_failure_already_exists(suricata_instance, settings, tmp_path):
    """Test Suricata.push() returns False when the reload file already exists."""
    settings.SURICATA_OUTPUT_DIRECTORY = str(tmp_path)

    # Create the file beforehand
    (tmp_path / "scirius.reload").write_text("dummy")

    assert suricata_instance.push() is False


# --- get_probe_hostnames tests ---


def test_get_probe_hostnames_settings_hostname(settings, mocker):
    """Test get_probe_hostnames returns system hostname if setting is True."""
    settings.SURICATA_NAME_IS_HOSTNAME = True
    mocker.patch("suricata.models.socket.gethostname", return_value="system-hostname")

    assert get_probe_hostnames() == ["system-hostname"]


def test_get_probe_hostnames_from_db(settings, suricata_instance):
    """Test get_probe_hostnames returns DB name if setting is False and probe exists."""
    settings.SURICATA_NAME_IS_HOSTNAME = False
    assert get_probe_hostnames() == ["mock-probe"]


def test_get_probe_hostnames_none_found(settings, db):
    """Test get_probe_hostnames returns None if no probes are found."""
    settings.SURICATA_NAME_IS_HOSTNAME = False
    Suricata.objects.all().delete()
    assert get_probe_hostnames() is None


@pytest.fixture
def mock_celery_task(db, mock_user, mock_ruleset):
    """Creates a CeleryTask instance for testing methods."""

    task = CeleryTask.objects.create(
        task="MockConcreteTask", user=mock_user, celery_id="CELERY_MOCK_ID", status="running", fired=timezone.now()
    )
    yield task
    task.delete()


def test_celerytask_str(mock_celery_task):
    """Test the string representation of CeleryTask."""
    assert str(mock_celery_task).startswith(f"CTask {mock_celery_task.id} MockConcreteTask ")


# --- CeleryTask Methods ---


def test_celerytask_set_finished_success(mock_celery_task, mocker):
    """Test set_finished when there is at least one successful result."""
    mocker.patch(
        "suricata.models.CeleryTaskResult.objects.filter",
        MagicMock(return_value=MagicMock(count=MagicMock(return_value=1))),
    )

    mock_celery_task.set_finished()

    assert mock_celery_task.status == "finished"
    assert mock_celery_task.success is True
    assert mock_celery_task.finished is not None


def test_celerytask_set_finished_failure(mock_celery_task, mocker):
    """Test set_finished when there are no successful results."""
    mocker.patch(
        "suricata.models.CeleryTaskResult.objects.filter",
        MagicMock(return_value=MagicMock(count=MagicMock(return_value=0))),
    )

    mock_celery_task.set_finished()

    assert mock_celery_task.status == "finished"
    assert mock_celery_task.success is False


def test_celerytask_revoke(mock_celery_task):
    """Test revoke sets status to 'revoked' and clears eta."""
    mock_celery_task.revoke()

    assert mock_celery_task.status == "revoked"
    assert mock_celery_task.eta is None


# --- CeleryTask Display and State Methods ---


def test_celerytask_get_state_revoked(mock_celery_task):
    """Test get_state returns 'REVOKED' when status is revoked."""
    mock_celery_task.status = "revoked"
    assert mock_celery_task.get_state() == "REVOKED"


def test_celerytask_get_state_pending_no_celery_id(mock_celery_task):
    """Test get_state handles race condition (no celery_id) returns 'PENDING'."""
    mock_celery_task.celery_id = None
    mock_celery_task.status = "scheduled"
    assert mock_celery_task.get_state() == "PENDING"


def test_celerytask_format_msg():
    """Test _format_msg correctly trims and joins the last 15 lines."""
    long_msg = "\n".join([f"line {i}" for i in range(20)])

    # The last 15 lines start at index 5
    expected = "\n".join([f"line {i}" for i in range(5, 20)])

    mock_celery_task = CeleryTask()  # Instance without DB state
    assert mock_celery_task._format_msg(long_msg) == expected
    assert mock_celery_task._format_msg(None) == ""
    assert mock_celery_task._format_msg("short msg\n") == "short msg"  # Test strip


# --- RecurrentTask Tests ---


@pytest.mark.parametrize(
    "recurrence, expected_interval",
    [
        ("hourly", 3600),
        ("daily", 86400),
        ("weekly", 604800),
        ("monthly", 2628000),
    ],
)
def test_recurrent_task_get_interval(db, mock_user, recurrence, expected_interval):
    """Test get_interval returns the correct seconds for each recurrence choice."""
    rtask = RecurrentTask(task="MockConcreteTask", recurrence=recurrence, scheduled=timezone.now(), user=mock_user)
    assert rtask.get_interval() == expected_interval


def test_recurrent_task_get_interval_invalid(db, mock_user):
    """Test get_interval raises exception for invalid recurrence."""
    rtask = RecurrentTask(task="MockConcreteTask", recurrence="yearly", scheduled=timezone.now(), user=mock_user)
    with pytest.raises(Exception, match="Invalid interval yearly"):
        rtask.get_interval()


def test_recurrent_task_next_run_time(db, mock_user):
    """Test next_run_time calculates the next run time correctly."""

    scheduled_time = datetime(2025, 1, 1, 10, 0, 0)
    rtask = RecurrentTask(task="MockConcreteTask", recurrence="daily", scheduled=scheduled_time, user=mock_user)
    interval = rtask.get_interval()  # 86400 seconds (1 day)

    # 1. ctime < scheduled (should return scheduled)
    ctime_before = scheduled_time - timedelta(hours=1)
    assert rtask.next_run_time(ctime_before) == scheduled_time

    # 2. ctime slightly after scheduled (should return scheduled + 1 interval)
    ctime_after = scheduled_time + timedelta(hours=1)
    expected_next = scheduled_time + timedelta(seconds=interval)
    assert rtask.next_run_time(ctime_after) == expected_next

    # 3. ctime after 2 full intervals (should return scheduled + 3 intervals)
    ctime_far = scheduled_time + timedelta(days=2, hours=1)
    expected_next_far = scheduled_time + timedelta(seconds=interval * 3)
    assert rtask.next_run_time(ctime_far) == expected_next_far


@freeze_time("2025-01-01 10:00:00")
def test_recurrent_task_schedule_run(db, mock_user, mocker):
    """Test schedule_run creates a CeleryTask (child) and uses task options."""

    rtask = RecurrentTask.objects.create(
        task="MockConcreteTask",
        user=mock_user,
        recurrence="daily",
        scheduled=timezone.now(),
        task_options=json.dumps({"option_a": 1, "option_b": 2}),
    )

    mock_celery_spawn = mocker.patch("suricata.models.CeleryTask.spawn")

    rtask.schedule_run(eta=datetime(2025, 1, 2, 10, 0, 0))

    # Check that spawn was called with all necessary arguments
    mock_celery_spawn.assert_called_once()
    args, kwargs = mock_celery_spawn.call_args

    assert args[0] == "MockConcreteTask"
    assert kwargs["schedule"] == datetime(2025, 1, 2, 10, 0, 0)
    assert kwargs["user"] == mock_user
    assert kwargs["rtask_parent"] == rtask
    assert kwargs["option_a"] == 1  # Check merged task_options
