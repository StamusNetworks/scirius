import os
import shutil
from collections.abc import Iterable
from pathlib import Path
from typing import TypedDict

import pytest
import structlog
from django.conf import settings
from django.contrib.auth.models import Group, User
from django.core import mail
from django.core.cache import cache
from django.test import Client
from rest_framework.test import APIClient

from accounts.models import SciriusUser


def prepare_test_files(test_base_dir: Path, git_sources_dir: Path):
    sid_file = git_sources_dir / "sid-ranges.yaml"
    if not sid_file.exists():
        source_sid = Path("debian/sid-ranges.yaml")
        if source_sid.exists():
            shutil.copy2(source_sid, sid_file)

    ansible_dirs = test_base_dir.parent / "appliances" / "templates" / "ansible"
    ansible_dirs.mkdir(parents=True, exist_ok=True)
    shutil.copytree(Path("appliances") / "templates" / "ansible", ansible_dirs, dirs_exist_ok=True)

    saml_dir = test_base_dir.parent / "saml"
    saml_dir.mkdir(parents=True, exist_ok=True)
    saml_dir = test_base_dir.parent / "lock"
    saml_dir.mkdir(parents=True, exist_ok=True)


@pytest.fixture(autouse=True)
def configure_structlog():
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.dev.ConsoleRenderer(),  # redable display for the console
        ],
        cache_logger_on_first_use=False,  # required for structlog.testing.capture_logs() to work
    )


@pytest.fixture(autouse=True)
def use_dummy_cache_backend(settings):
    settings.CACHES = {"default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}}


@pytest.fixture
def clean_cache():
    """
    Fixture to clean cache before each test.
    """
    cache.clear()
    yield
    cache.clear()


# to mock settings, use this: https://pytest-django.readthedocs.io/en/latest/helpers.html#settings

pytest_plugins = [
    "pytest_django",
]


def pytest_configure(config):
    """Custom markers for pytest."""
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "unit: marks tests as unit tests")
    # config.addinivalue_line("markers", "webtest: marks tests that require selenium")


def pytest_collection_modifyitems(config, items: Iterable[str]):
    """
    Hook to optimize performance in the test clollect
    """
    for item in items:
        # if the test contains 'slow' in the name mark it as slow
        if "slow" in item.name.lower():
            item.add_marker(pytest.mark.slow)

        # mark test depending on the location
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)


@pytest.fixture
def mailoutbox():
    """
    Fixture that gives access to a mailbox to test email sending.
    Mailbox is cleaned after each test.
    """
    mail.outbox.clear()
    yield mail.outbox
    mail.outbox.clear()


@pytest.fixture(scope="session", autouse=True)
def prepare_test_environment():
    """
    Prepare environment once per test session
    """
    # and create directories
    git_sources_dir = settings.GIT_SOURCES_BASE_DIRECTORY
    git_rulesets_dir = settings.GIT_RULESETS_BASE_DIRECTORY

    git_sources_dir.mkdir(parents=True, exist_ok=True)
    git_rulesets_dir.mkdir(parents=True, exist_ok=True)

    # copy needed files
    prepare_test_files(settings.GENERATED_BASE_DIR, git_sources_dir)

    return settings.BASE_DIR


@pytest.fixture(scope="session", autouse=True)
def setup_custom_home(tmp_path_factory: pytest.TempPathFactory):
    """
    Change the home to avoid the override of ~/.ssh/config with ansible
    """
    temp_dir = tmp_path_factory.mktemp("scirius_home")
    os.environ["HOME"] = str(temp_dir)
    ssh_dir = temp_dir / ".ssh"
    ssh_dir.mkdir()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


class DefaultProfile(TypedDict):
    user: User
    scirius_user: SciriusUser

    superuser_role: Group
    staff_role: Group
    user_role: Group


@pytest.fixture
def default_profile(db, client: Client):
    """
    Create default user and roles
    """
    user = User.objects.create(username="default_scirius", password="scirius", is_superuser=False, is_staff=False)  # noqa: S106
    su_role = Group.objects.get(name="Superuser")
    su_role.user_set.add(user)
    return DefaultProfile(
        user=user,
        scirius_user=SciriusUser.objects.create(user=user, timezone="UTC"),
        superuser_role=su_role,
        staff_role=Group.objects.get(name="Staff"),
        user_role=Group.objects.get(name="User"),
    )


@pytest.fixture
def drf(default_profile: DefaultProfile):
    client = APIClient()
    client.force_authenticate(user=default_profile["user"])
    return client
