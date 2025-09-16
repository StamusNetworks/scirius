from typing import Iterable

import pytest
import shutil

from pathlib import Path

from django.conf import settings
from django.core import mail
from django.core.cache import cache


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

    yield settings.BASE_DIR
