from typing import TypedDict
import pytest
from copy import deepcopy

from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from rules.models.model import (
    Category,
    Rule,
    RuleAtVersion,
    RuleProcessingFilterDef,
    Ruleset,
    Source,
    RuleProcessingFilter,
    UserAction,
)


def detail_url(x):
    return reverse("ruleprocessingfilter-detail", args=(x,))


list_url = reverse("ruleprocessingfilter-list")


class TestData(TypedDict):
    source: Source
    category: Category
    ruleset: Ruleset
    default_filter: dict
    default_filter2: dict


@pytest.fixture
def setup_data(db) -> TestData:
    source = Source.objects.create(name="test source", created_date=timezone.now(), method="local", datatype="sig")
    source.save()
    category = Category.objects.create(name="test category", filename="test", source=source)
    category.save()

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

    rule2 = Rule.objects.create(sid=2, category=category, msg="whatever DNS Query for whatever")
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
    ruleset.save()
    ruleset.sources.add(source)
    ruleset.categories.add(category)

    return {
        "source": source,
        "category": category,
        "ruleset": ruleset,
        "default_filter": {
            "filter_defs": [{"key": "event_type", "value": "http", "operator": "equal", "full_string": True}],
            "action": "suppress",
            "index": 0,
            "rulesets": [ruleset.pk],
        },
        "default_filter2": {
            "filter_defs": [{"key": "host", "value": "probe-test", "operator": "equal", "full_string": True}],
            "action": "suppress",
            "index": 0,
            "rulesets": [ruleset.pk],
        },
    }


def test_013_suppress_validation_error(drf: APIClient, setup_data: TestData):
    f = deepcopy(setup_data["default_filter"])
    f["options"] = {"test": "test"}
    resp = drf.post(list_url, f)
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    r = resp.json()
    assert r == {"options": ['Action "suppress" does not accept options.']}


def test_015_threshold_create_invalid(drf: APIClient, setup_data: TestData):
    resp = drf.post(
        list_url,
        {
            "filter_defs": [{"key": "alert.sid", "value": "1", "operator": "equal", "full_string": True}],
            "action": "threshold",
            "options": {"count": 2, "seconds": 30, "track": "by_src"},
            "rulesets": [setup_data["ruleset"].pk],
        },
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    r = resp.json()
    assert r == {"options": [{"type": ["This field is required."]}]}


def test_019_suri_filter_defs_invalid(settings, drf: APIClient, setup_data: TestData):
    settings.RULESET_MIDDLEWARE = "suricata"
    resp = drf.post(
        list_url,
        {
            "filter_defs": [{"key": "src_ip", "value": "192.168.0.1", "operator": "equal", "full_string": True}],
            "action": "suppress",
            "rulesets": [setup_data["ruleset"].pk],
        },
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    r = resp.json()
    assert r == {
        "filter_defs": [
            'A filter with a key "alert.signature_id" or "msg" or "alert.signature" or "content" is required.'
        ]
    }


def test_020_suri_suppress_generate(drf: APIClient, setup_data: TestData):
    resp = drf.post(
        list_url,
        {
            "filter_defs": [
                {"key": "src_ip", "value": "192.168.0.1", "operator": "equal"},
                {"key": "alert.signature_id", "value": "1", "operator": "equal"},
            ],
            "action": "suppress",
            "rulesets": [setup_data["ruleset"].pk],
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED

    f = RuleProcessingFilter.objects.all()[0]
    suppress = f.get_threshold_content()
    assert suppress == ["suppress gen_id 1, sid_id 1, track by_src, ip 192.168.0.1\n"]


def test_021_suri_threshold_generate(drf: APIClient, setup_data: TestData):
    resp = drf.post(
        list_url,
        {
            "filter_defs": [
                {"key": "dest_ip", "value": "192.168.0.1", "operator": "equal", "full_string": True},
                {"key": "alert.signature_id", "value": "1", "operator": "equal", "full_string": True},
            ],
            "action": "threshold",
            "options": {"type": "both", "track": "by_dst"},
            "rulesets": [setup_data["ruleset"].pk],
        },
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST

    assert resp.json() == {"filter_defs": ['Field "dest_ip" is not supported for threshold.']}


def test_022_ip_validation(drf: APIClient, setup_data: TestData):
    resp = drf.post(
        list_url,
        {
            "filter_defs": [{"key": "dest_ip", "value": "192.168.0.", "operator": "equal"}],
            "action": "suppress",
            "rulesets": [setup_data["ruleset"].pk],
        },
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json() == {"filter_defs": [{"value": ["This field requires a valid IP address."]}]}


def test_023_capabilities_test(settings, drf: APIClient, setup_data: TestData):
    settings.RULESET_MIDDLEWARE = "suricata"
    resp = drf.post(reverse("ruleprocessingfilter-test"), {"fields": ["src_ip", "dns.rdata"], "action": "suppress"})
    assert resp.status_code == status.HTTP_200_OK
    r = resp.json()
    supported_fields = sorted(r.pop("supported_fields").split(", "))
    assert r == {"fields": ["src_ip"], "operators": ["equal"]}
    assert supported_fields == [
        "alert.signature",
        "alert.signature_id",
        "alert.source.ip",
        "alert.target.ip",
        "content",
        "dest_ip",
        "msg",
        "src_ip",
    ]


def test_024_capabilities_test(settings, drf: APIClient, setup_data: TestData):
    settings.RULESET_MIDDLEWARE = "suricata"
    resp = drf.post(reverse("ruleprocessingfilter-test"), {"fields": ["src_ip", "dns.rdata"], "action": "threshold"})
    assert resp.status_code == status.HTTP_200_OK
    r = resp.json()
    supported_fields = sorted(r.pop("supported_fields").split(", "))
    assert r == {"fields": [], "operators": ["equal"]}
    assert supported_fields == ["alert.signature", "alert.signature_id", "content", "msg"]


def test_124_srcip_msg_validation(settings, drf: APIClient, setup_data: TestData):
    settings.RULESET_MIDDLEWARE = "suricata"
    resp = drf.post(
        list_url,
        {
            "filter_defs": [
                {"key": "src_ip", "value": "192.168.0.1", "operator": "equal"},
                {"key": "msg", "value": "DNS Query for", "operator": "equal"},
            ],
            "action": "suppress",
            "rulesets": [setup_data["ruleset"].pk],
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED

    f = RuleProcessingFilter.objects.all()[0]
    suppress = f.get_threshold_content(setup_data["ruleset"])
    assert suppress == [
        "suppress gen_id 1, sid_id 2, track by_src, ip 192.168.0.1\n",
        "suppress gen_id 1, sid_id 3, track by_src, ip 192.168.0.1\n",
        "suppress gen_id 1, sid_id 4, track by_src, ip 192.168.0.1\n",
    ]


def test_125_target_src_msg_validation(settings, drf: APIClient, setup_data: TestData):
    settings.RULESET_MIDDLEWARE = "suricata"
    resp = drf.post(
        list_url,
        {
            "filter_defs": [
                {"key": "alert.target.ip", "value": "192.168.0.1", "operator": "equal"},
                {"key": "msg", "value": "another content", "operator": "equal"},
            ],
            "action": "suppress",
            "rulesets": [setup_data["ruleset"].pk],
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED

    f = RuleProcessingFilter.objects.all()[0]
    suppress = f.get_threshold_content(setup_data["ruleset"])
    assert suppress == [
        "suppress gen_id 1, sid_id 3, track by_dst, ip 192.168.0.1\n",
        "suppress gen_id 1, sid_id 4, track by_src, ip 192.168.0.1\n",
    ]


def _remove_filters_pk(f):
    for f_def in f["filter_defs"]:
        f_def.pop("pk", None)


@pytest.fixture
def ruleset(db) -> Ruleset:
    source = Source.objects.create(name="test source", created_date=timezone.now(), method="local", datatype="sig")
    source.save()
    category = Category.objects.create(name="test category", filename="test", source=source)
    category.save()

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

    rule2 = Rule.objects.create(sid=2, category=category, msg="whatever DNS Query for whatever")
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
    ruleset.save()
    ruleset.sources.add(source)
    ruleset.categories.add(category)
    return ruleset


@pytest.fixture
def default_filter(db, ruleset: Ruleset):
    return {
        "filter_defs": [{"key": "event_type", "value": "http", "operator": "equal", "full_string": True}],
        "action": "suppress",
        "index": 0,
        "rulesets": [ruleset.pk],
    }


def test_001_create(db, drf: APIClient, default_filter):
    default_filter["comment"] = "test comment"
    resp = drf.post(list_url, default_filter)
    assert resp.status_code == status.HTTP_201_CREATED
    r = resp.json()
    _remove_filters_pk(r)
    assert r == r | default_filter
    ua = UserAction.objects.last()
    assert ua.action_type == "create_rule_filter"
    assert ua.comment, "test comment"


def test_002_create_invalid_filter(db, drf: APIClient, default_filter):
    f = deepcopy(default_filter)
    f["filter_defs"] = []
    resp = drf.post(list_url, f)
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json() == {"filter_defs": ["This field is required."]}
    assert RuleProcessingFilter.objects.count() == 0
    assert RuleProcessingFilterDef.objects.count() == 0

    f = deepcopy(default_filter)
    f["filter_defs"] = [{"key": "test", "operator": "equal"}]
    resp = drf.post(list_url, f)
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json() == {"filter_defs": [{"value": ["This field is required."]}]}
    assert RuleProcessingFilter.objects.count() == 0
    assert RuleProcessingFilterDef.objects.count() == 0


def test_003_update_filter_existing(db, drf: APIClient, default_filter):
    f = deepcopy(default_filter)
    # create the same filter from test_001_create
    f["comment"] = "test comment"
    resp = drf.post(list_url, f)
    r = resp.json()
    filter_pk = r["pk"]
    _remove_filters_pk(r)

    resp = drf.patch(
        detail_url(filter_pk),
        {"filter_defs": [{"key": "event_type", "value": "dns", "operator": "equal"}], "comment": "test comment"},
    )
    assert resp.status_code == status.HTTP_200_OK
    r = resp.json()

    f = deepcopy(default_filter)
    f["filter_defs"][0]["value"] = "dns"
    _remove_filters_pk(r)
    assert r == r | f

    ua = UserAction.objects.last()
    assert ua.action_type == "edit_rule_filter"
    assert ua.comment == "test comment"


def test_004_update_filter_add(db, drf: APIClient, default_filter):
    f = deepcopy(default_filter)
    # create the same filter from test_001_create
    f["comment"] = "test comment"
    resp = drf.post(list_url, f)
    r = resp.json()
    filter_pk = r["pk"]
    _remove_filters_pk(r)

    # Filter value update
    new_filter = {"key": "host", "value": "probe1", "operator": "equal", "full_string": True}
    filters = deepcopy(default_filter["filter_defs"])
    filters.append(new_filter)

    resp = drf.patch(detail_url(filter_pk), {"filter_defs": filters})
    assert resp.status_code == status.HTTP_200_OK
    r = resp.json()

    f = deepcopy(default_filter)
    f["filter_defs"].append(new_filter)
    _remove_filters_pk(r)
    assert r == r | f
    assert len(r["filter_defs"]) == 2


def test_005_update_filter_rm(db, drf: APIClient, default_filter):
    f = deepcopy(default_filter)
    f["filter_defs"].append({"key": "host", "value": "probe1", "operator": "equal", "full_string": True})

    resp = drf.post(list_url, f)
    assert resp.status_code == status.HTTP_201_CREATED
    r = resp.json()
    r["filter_defs"][0].pop("pk")
    r["filter_defs"][1].pop("pk")
    assert r == r | f

    resp = drf.patch(detail_url(r["pk"]), {"filter_defs": default_filter["filter_defs"]})
    assert resp.status_code == status.HTTP_200_OK
    r = resp.json()

    _remove_filters_pk(r)
    assert r == r | default_filter
    assert len(r["filter_defs"]) == 1


def test_006_order_create_empty(db, drf: APIClient, default_filter):
    f = deepcopy(default_filter)
    f.pop("index")

    resp = drf.post(list_url, f)
    assert resp.status_code == status.HTTP_201_CREATED
    r = resp.json()
    _remove_filters_pk(r)
    assert r == r | default_filter


def test_007_order_create_append(db, drf: APIClient, default_filter):
    f = deepcopy(default_filter)
    # create the same filter from test_001_create
    f["comment"] = "test comment"
    resp = drf.post(list_url, f)
    r = resp.json()
    _remove_filters_pk(r)

    DEFAULT_FILTER2 = {
        "filter_defs": [{"key": "host", "value": "probe-test", "operator": "equal", "full_string": True}],
        "action": "suppress",
        "index": 0,
        "rulesets": [Ruleset.objects.first().pk],
    }

    f = deepcopy(DEFAULT_FILTER2)
    f.pop("index")

    resp = drf.post(list_url, f)
    assert resp.status_code == status.HTTP_201_CREATED
    r = resp.json()
    _remove_filters_pk(r)
    f = deepcopy(DEFAULT_FILTER2)
    f["index"] = 1

    assert r == r | f

    resp = drf.get(list_url)
    assert resp.status_code == status.HTTP_200_OK
    r = resp.json()
    _remove_filters_pk(r["results"][0])
    result = r["results"][0]
    assert result == result | default_filter
    _remove_filters_pk(r["results"][1])
    result = r["results"][1]
    assert result == result | f


def test_008_order_create_insert(db, drf: APIClient, default_filter):
    f = deepcopy(default_filter)
    # create the same filter from test_001_create
    f["comment"] = "test comment"
    resp = drf.post(list_url, f)
    r = resp.json()
    _remove_filters_pk(r)

    DEFAULT_FILTER2 = {
        "filter_defs": [{"key": "host", "value": "probe-test", "operator": "equal", "full_string": True}],
        "action": "suppress",
        "index": 0,
        "rulesets": [Ruleset.objects.first().pk],
    }

    resp = drf.post(list_url, DEFAULT_FILTER2)
    assert resp.status_code == status.HTTP_201_CREATED
    r = resp.json()

    f1 = deepcopy(default_filter)
    f1["index"] = 1

    resp = drf.get(list_url)
    assert resp.status_code == status.HTTP_200_OK
    r = resp.json()
    _remove_filters_pk(r["results"][0])
    result = r["results"][0]
    assert result == result | DEFAULT_FILTER2
    _remove_filters_pk(r["results"][1])
    result = r["results"][1]
    assert result == result | f1


def test_009_order_create_oob(db, drf: APIClient, default_filter):
    f = deepcopy(default_filter)
    f["index"] = 1
    resp = drf.post(list_url, f)
    assert resp.status_code == status.HTTP_400_BAD_REQUEST

    assert resp.json() == {"index": ["Invalid index value (too high)."]}


@pytest.mark.parametrize("prev_index", range(4))
@pytest.mark.parametrize("new_index", [*list(range(5)), None])
def _test_010_order_update(prev_index, new_index, default_filter, drf):
    filters = []
    for _i in range(4):
        f = deepcopy(default_filter)
        f.pop("index")
        resp = drf.post(list_url, f)
        assert resp.status_code == status.HTTP_201_CREATED
        r = resp.json()
        filters.append(r["pk"])

    pk_to_move = filters[prev_index]
    expected = deepcopy(filters)

    if new_index is None:
        expected.pop(prev_index)
        expected.append(pk_to_move)
    else:
        if prev_index != new_index:
            expected.pop(prev_index)

            if new_index < len(filters):
                insert_before_pk = filters[new_index]
                _new_index = expected.index(insert_before_pk)
                expected.insert(_new_index, pk_to_move)
            else:
                expected.append(pk_to_move)

    resp = drf.patch(detail_url(pk_to_move), {"index": new_index})
    assert resp.status_code == status.HTTP_200_OK

    # check order
    resp = drf.get(list_url)
    assert resp.status_code == status.HTTP_200_OK
    r = resp.json()
    order = [f["pk"] for f in r["results"]]
    assert expected == order
    indices = [f["index"] for f in r["results"]]
    assert indices == list(range(4))


def test_011_order_update_oob(db, drf: APIClient, default_filter):
    f = deepcopy(default_filter)
    # create the same filter from test_001_create
    f["comment"] = "test comment"
    resp = drf.post(list_url, f)
    r = resp.json()
    filter_pk = r["pk"]
    _remove_filters_pk(r)

    resp = drf.patch(detail_url(filter_pk), {"index": 2})
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json() == {"index": ["Invalid index value (too high)."]}


def test_012_delete(db, drf: APIClient, default_filter):
    test_007_order_create_append(db, drf, default_filter)

    DEFAULT_FILTER2 = {
        "filter_defs": [{"key": "host", "value": "probe-test", "operator": "equal", "full_string": True}],
        "action": "suppress",
        "index": 0,
        "rulesets": [Ruleset.objects.first().pk],
    }

    resp = drf.delete(detail_url(RuleProcessingFilter.objects.first().pk), {"comment": "test comment"})
    assert resp.status_code == status.HTTP_204_NO_CONTENT
    resp = drf.get(list_url)
    assert resp.status_code == status.HTTP_200_OK
    r = resp.json()

    assert r["count"] == 1
    _remove_filters_pk(r["results"][0])
    result = r["results"][0]
    assert result == result | DEFAULT_FILTER2

    ua = UserAction.objects.last()
    assert ua.action_type == "delete_rule_filter"
    assert ua.comment == "test comment"


def test_014_threshold_create(db, drf: APIClient, default_filter):
    f = {
        "filter_defs": [
            {
                "key": "alert.signature_id",
                "value": "1",
                "operator": "equal",
                "full_string": True,
                "msg": "test rule",
            }
        ],
        "action": "threshold",
        "options": {"type": "both", "count": 2, "seconds": 30, "track": "by_src"},
        "rulesets": [Ruleset.objects.first().pk],
    }
    resp = drf.post(list_url, f)
    assert resp.status_code == status.HTTP_201_CREATED
    r = resp.json()
    _remove_filters_pk(r)
    assert r == r | f


def test_016_threshold_update(db, drf: APIClient, default_filter):
    test_014_threshold_create(db, drf, default_filter)
    resp = drf.patch(detail_url(RuleProcessingFilter.objects.last().pk), {"action": "suppress", "options": {}})
    assert resp.status_code == status.HTTP_200_OK


def test_017_threshold_update_invalid(db, drf: APIClient, default_filter):
    test_014_threshold_create(db, drf, default_filter)
    resp = drf.patch(detail_url(RuleProcessingFilter.objects.last().pk), {"action": "threshold", "options": {}})
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json() == {"options": [{"type": ["This field is required."], "track": ["This field is required."]}]}


def test_025_intersect_match(db, drf: APIClient, default_filter):
    test_007_order_create_append(db, drf, default_filter)

    conflict_filter = {
        "filter_defs": [{"key": "event_type", "value": "dns", "operator": "equal"}],
    }
    resp = drf.post(reverse("ruleprocessingfilter-intersect"), conflict_filter)
    assert resp.status_code == status.HTTP_200_OK
    r = resp.json()
    assert r.get("count") == 1
    result = r["results"][0]
    _remove_filters_pk(result)
    assert result == result | default_filter


def test_026_intersect_multi_match(db, drf: APIClient, default_filter):
    test_007_order_create_append(db, drf, default_filter)

    conflict_filter = {
        "filter_defs": [
            {"key": "event_type", "value": "dns", "operator": "equal"},
            {"key": "host", "value": "test42", "operator": "contains"},
        ],
    }
    resp = drf.post(reverse("ruleprocessingfilter-intersect"), conflict_filter)
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json().get("count") == 2


def test_027_intersect_no_match(db, drf: APIClient, default_filter):
    test_007_order_create_append(db, drf, default_filter)

    conflict_filter = {
        "filter_defs": [{"key": "alert.signature_id", "value": "dns", "operator": "equal"}],
    }
    resp = drf.post(reverse("ruleprocessingfilter-intersect"), conflict_filter)
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json().get("count") == 0


def test_028_create(db, drf: APIClient, default_filter):
    f = deepcopy(default_filter)
    f["filter_defs"] = [
        {"key": "event_type", "value": "dns", "operator": "different", "full_string": True},
        {"key": "event_type", "value": "http", "operator": "different", "full_string": True},
    ]

    resp = drf.post(list_url, f)
    assert resp.status_code == status.HTTP_201_CREATED
    r = resp.json()
    _remove_filters_pk(r)
    assert r == r | f
