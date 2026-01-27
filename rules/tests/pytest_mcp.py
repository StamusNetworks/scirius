import pytest

from django.contrib.auth.models import Group, User
from django.test import RequestFactory
from django.utils import timezone
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
    """Simulate a DRF Request with auth user"""
    request = rf.get("/")
    request.user = mcp_user
    force_authenticate(request, user=mcp_user)
    # raise Exception(request, type(request))
    return Request(request)


@pytest.mark.django_db
def test_without_data(mcp_request: Request):
    """
    Test MCP ednpoints without data, just for a coverage and check no exception occurs
    """

    controller = McpController(request=mcp_request)

    controller.version()

    controller.rules_search("dummy")


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

    rule2 = Rule.objects.create(sid=2, category=category, msg="whatever DNS Query for whatever", created=timezone.localdate())
    rule2.save()
    RuleAtVersion.objects.create(rule=rule2, content=content)

    rule3 = Rule.objects.create(
        sid=3, category=category, msg="other content DNS Query for another content"
    )
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

    results = controller.rules_search("does not exist")
    assert len(results) == 0
