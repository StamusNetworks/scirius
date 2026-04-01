import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
import structlog
import structlog.testing
from django.contrib.auth.models import Group, Permission, User
from django.test import RequestFactory
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied
from rest_framework.request import Request
from rest_framework.test import force_authenticate

from accounts.models import SciriusUser
from rules.mcp import McpController
from rules.models.model import (
    Category,
    Rule,
    RuleAtVersion,
    Ruleset,
    Source,
)


@pytest.fixture
def mcp_user(db):
    from scirius.utils import get_middleware_module

    superuser_role = Group.objects.get(name="Superuser")

    django_user = User.objects.create(username="pytester", password="scirius", is_superuser=False, is_staff=False)  # noqa: S106
    SciriusUser.objects.get_or_create(user=django_user, defaults={"timezone": "UTC"})
    get_middleware_module("common").update_scirius_user_class(django_user, {})

    superuser_role.user_set.add(django_user)
    return django_user


@pytest.fixture
def mcp_request(rf: RequestFactory, mcp_user: User) -> Request:
    return _create_request(rf, mcp_user)


def _create_request(rf: RequestFactory, mcp_user: User) -> Request:
    """
    Simulate a DRF Request with auth user

    Not in the fixture because we need it when checking perms
    """
    request = rf.get("/")
    request.user = mcp_user
    force_authenticate(request, user=mcp_user)
    return Request(request)


@pytest.mark.django_db
def test_without_data(mcp_request: Request):
    """
    Test MCP ednpoints without data, just for a coverage and check no exception occurs
    """

    controller = McpController(request=mcp_request)

    controller.version()

    controller.rules_search("dummy")


def _create_user(
    username: str,
    group: str = "test",
    group_perms: list[Permission] | None = None,
    *,
    is_superuser: bool = False,
    is_staff: bool = True,
):
    u = User.objects.create(username=username, password="scirius2", is_superuser=is_superuser, is_staff=is_staff)  # noqa: S106
    g = Group.objects.create(name=group)
    if group_perms:
        g.permissions.set(group_perms)
    u.groups.add(g)
    data = {"timezone": "UTC"}
    return SciriusUser.create_full(u, data)


@pytest.mark.django_db
def test_group_perms(rf: RequestFactory):
    # user with no permission
    user = _create_user(username="almost-anonymous", group="nopermgroup")
    request = _create_request(rf, user)
    controller = McpController(request=request)

    with pytest.raises(PermissionDenied, match="No group permission"):
        controller.rules_search("should be forbidden")

    # user with perms for the endpoint
    perm1 = Permission.objects.get(codename="source_view")
    perm2 = Permission.objects.get(codename="ruleset_policy_view")
    user = _create_user(username="mcp-user", group="mcpgroup", group_perms=[perm1, perm2])
    request = _create_request(rf, user)
    controller = McpController(request=request)
    controller.rules_search("should be OK")


@pytest.mark.django_db
def test_mcp_rules(mcp_request: Request):
    controller = McpController(request=mcp_request)

    source = Source.objects.create(name="test source", created_date=timezone.now(), method="local", datatype="sig")
    category = Category.objects.create(name="test category", filename="test", source=source)

    content = (
        'alert ip $HOME_NET any -> [103.207.29.161,103.207.29.171,103.225.168.222,103.234.36.190,103.234.37.4,103.4.164.34, \
103.6.207.37,104.131.93.109,104.140.137.152,104.143.5.144,104.144.167.131,104.144.167.251,104.194.206.108, \
104.199.121.36,104.207.154.26,104.223.87.207,104.43.200.222,106.187.48.236,107.161.19.71] \
any (msg:"whatever DNS Query for whatever"; \
reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,www.shadowserver.org;\
threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; \
flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404000; rev:4933;)'
    )

    content2 = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"other content DNS Query for other content"; \
flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB2"; within:5; distance:3; content:"|01 00|"; \
within:2; distance:56; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103141; \
rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23; target:dest_ip;)'

    content3 = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"other content DNS Query for other content"; \
flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB2"; within:5; distance:3; content:"|01 00|"; \
within:2; distance:56; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103141; \
rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23; target:src_ip;)'

    rule = Rule.objects.create(sid=1, category=category, msg="test rule")
    rule.save()
    RuleAtVersion.objects.create(rule=rule, content=content)

    rule2 = Rule.objects.create(
        sid=2, category=category, msg="whatever DNS Query for whatever", created=timezone.localdate()
    )
    rule2.save()
    RuleAtVersion.objects.create(rule=rule2, content=content)

    rule3 = Rule.objects.create(sid=3, category=category, msg="other content DNS Query for another content")
    rule3.save()
    RuleAtVersion.objects.create(rule=rule3, content=content2)

    rule4 = Rule.objects.create(sid=4, category=category, msg="other content DNS Query for another content")
    rule4.save()
    RuleAtVersion.objects.create(rule=rule4, content=content3)

    ruleset = Ruleset.objects.create(
        name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
    )
    ruleset.sources.add(source)
    ruleset.categories.add(category)

    results = controller.rules_search("dns Query")
    assert len(results) == 3

    results = controller.rules_search("dns Query", page=1, limit=1)
    assert len(results) == 1
    assert results[0].sid == 2
    assert results[0].source == "test source"
    assert results[0].category == "test category"
    assert results[0].in_rulesets == ["test ruleset"]
    assert results[0].suricata_rule == content

    # get the last version of the rule content
    RuleAtVersion.objects.create(rule=rule2, version=1, content=f"{content} RANDOM TEXT")
    results = controller.rules_search("whatever DNS", page=1)
    assert results[0].suricata_rule == f"{content} RANDOM TEXT"

    results = controller.rules_search("does not exist")
    assert len(results) == 0


@pytest.mark.django_db
@pytest.mark.parametrize("ruleset_middleware", ["suricata", os.environ.get("RULESET_MIDDLEWARE", "suricata")])
def test_mcp_top_or_least_key(settings, ruleset_middleware: str, mcp_request: Request):
    settings.RULESET_MIDDLEWARE = ruleset_middleware
    # basic test for coverage, does not perform the OpenSearch query
    start_date = datetime(2026, 1, 1, tzinfo=UTC)
    end_date = datetime(2026, 1, 15, tzinfo=UTC)
    mock_data = {
        "dummy.key": [{"key": "Hello world", "doc_count": 79}],
        "another.key": [{"key": "", "doc_count": 32}],
    }

    with patch("rules.services.mcp.AnalyticRepository") as mock_es_class:
        mock_instance = MagicMock()
        mock_es_class.return_value = mock_instance
        mock_instance.fields_stats.return_value = mock_data

        controller = McpController(request=mcp_request)
        result = controller.top_or_least_keys(
            ["dummy.key", "another.key"], top=True, start=start_date, end=end_date, limit=20
        )

        assert "dummy.key" in result
        assert "another.key" in result
        assert result["dummy.key"][0].key == "Hello world"
        assert result["dummy.key"][0].doc_count == 79
        mock_instance.fields_stats.assert_called_once()
        _args, kwargs = mock_instance.fields_stats.call_args
        assert kwargs["limit"] == 20
        assert kwargs["top"]
        assert "dummy.key" in kwargs["fields"]
        assert "another.key" in kwargs["fields"]


# --- Logging tests ---


def test_mcp_logging_on_call_for_version(mcp_request: Request):
    """INFO log with tool name is emitted on a successful undecorated call (version)"""
    with structlog.testing.capture_logs() as cap_logs:
        controller = McpController(request=mcp_request)
        controller.version()

    info_events = [
        entry for entry in cap_logs if entry.get("log_level") == "info" and entry.get("event") == "mcp.tool_called"
    ]
    assert len(info_events) == 1
    assert info_events[0]["tool"] == "version"

    debug_events = [
        entry for entry in cap_logs if entry.get("log_level") == "debug" and entry.get("event") == "mcp.tool_response"
    ]
    assert len(debug_events) == 1
    assert debug_events[0]["tool"] == "version"


@pytest.mark.django_db
def test_mcp_logging_input_params(mcp_request: Request):
    """INFO log includes the exact input parameters passed to the tool"""
    with structlog.testing.capture_logs() as cap_logs:
        controller = McpController(request=mcp_request)
        controller.rules_search(query="dns query", page=2, limit=5)

    info_events = [
        entry for entry in cap_logs if entry.get("log_level") == "info" and entry.get("event") == "mcp.tool_called"
    ]
    assert len(info_events) == 1
    log = info_events[0]
    assert log["tool"] == "rules_search"
    assert log["query"] == "dns query"
    assert log["page"] == 2
    assert log["limit"] == 5


@pytest.mark.django_db
def test_mcp_logging_response_result_count(mcp_request: Request):
    """DEBUG response log includes result_count for list results"""
    with structlog.testing.capture_logs() as cap_logs:
        controller = McpController(request=mcp_request)
        controller.rules_search("no match here at all zzz")

    debug_events = [
        entry for entry in cap_logs if entry.get("log_level") == "debug" and entry.get("event") == "mcp.tool_response"
    ]
    assert len(debug_events) == 1
    assert debug_events[0]["tool"] == "rules_search"
    assert debug_events[0]["result_count"] == 0


@pytest.mark.django_db
def test_mcp_logging_permission_denied_warning(rf: RequestFactory):
    """WARNING log is emitted when the user lacks required group permissions"""
    user = _create_user(username="noperm-log-test", group="logtest-noperm")
    request = _create_request(rf, user)
    controller = McpController(request=request)

    with structlog.testing.capture_logs() as cap_logs, pytest.raises(PermissionDenied):
        controller.rules_search("test")

    warn_events = [
        entry
        for entry in cap_logs
        if entry.get("log_level") == "warning" and entry.get("event") == "mcp.permission_denied"
    ]
    assert len(warn_events) == 1
    assert warn_events[0]["reason"] == "no_group_permission"
    assert warn_events[0]["tool"] == "rules_search"


@pytest.mark.django_db
def test_mcp_logging_error_on_service_exception(mcp_request: Request):
    """ERROR log is emitted when the underlying service raises an unexpected exception"""
    with (
        patch("rules.services.mcp.McpService.rules_search", side_effect=RuntimeError("OpenSearch down")),
        structlog.testing.capture_logs() as cap_logs,
    ):
        controller = McpController(request=mcp_request)
        with pytest.raises(RuntimeError):
            controller.rules_search("test")

    error_events = [
        entry for entry in cap_logs if entry.get("log_level") == "error" and entry.get("event") == "mcp.tool_error"
    ]
    assert len(error_events) == 1
    assert error_events[0]["tool"] == "rules_search"
