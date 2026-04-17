from collections.abc import Callable
from typing import TypedDict
import pytest

from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from rules.models.model import (
    Category,
    CategoryTransformation,
    Rule,
    RuleAtVersion,
    Ruleset,
    RulesetTransformation,
    RuleTransformation,
    Source,
    Transformation,
)
from rules.services.transformation import TransformationService


class TestData(TypedDict):
    source: Source
    category: Category
    rule_commented: Rule
    rule_lateral_yes: Rule
    rule_lateral_auto_no_transfo: Rule
    rule_lateral_auto_transfo: Rule
    rule_target_auto_transfo: Rule
    rule_target_auto_no_transfo: Rule
    rule_target_source_transfo: Rule
    rule_target_destination_transfo: Rule
    rule_with_target: Rule


@pytest.fixture
def setup_objects(db) -> TestData:
    source = Source.objects.create(name="test source", created_date=timezone.now(), method="local", datatype="sig")
    source.save()
    category = Category.objects.create(name="test category", filename="test", source=source)
    category.save()

    # Commented rule
    content = '#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Trans2 FIND_FIRST2 attempt"; \
flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB2"; within:5; distance:3; content:"|01 00|"; \
within:2; distance:56; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103141; \
rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)'

    rule_commented = Rule.objects.create(sid=1, category=category, msg="test commented rule")
    rule_commented.save()
    RuleAtVersion.objects.create(rule=rule_commented, content=content)

    # Lateral yes
    content = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP Overflow Attempt"; flow:to_server,established; \
content:"|E8 C0 FF FF FF|/bin/sh"; classtype:attempted-admin; sid:2100293; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)'

    rule_lateral_yes = Rule.objects.create(sid=2, category=category, msg="test lateral yes")
    rule_lateral_yes.save()
    RuleAtVersion.objects.create(rule=rule_lateral_yes, content=content)

    # Lateral auto
    content = 'alert dns $HOME_NET any -> any any (msg:"ET POLICY DNS Query to .onion proxy Domain (onion. sx)"; dns_query; \
content:".onion.sx"; nocase; isdataat:!1,relative; metadata: former_category POLICY; \
reference:url,en.wikipedia.org/wiki/Tor_(anonymity_network); classtype:bad-unknown; sid:2025446; rev:2; \
metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, \
deployment Perimeter, signature_severity Minor, created_at 2018_03_28, performance_impact Moderate, updated_at 2018_03_30;)'

    rule_lateral_auto_no_transfo = Rule.objects.create(sid=3, category=category, msg="test lateral auto => no transfo")
    rule_lateral_auto_no_transfo.save()
    RuleAtVersion.objects.create(rule=rule_lateral_auto_no_transfo, content=content)

    content = (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'
    )

    rule_lateral_auto_transfo = Rule.objects.create(sid=4, category=category, msg="test lateral auto => transfo")
    rule_lateral_auto_transfo.save()
    RuleAtVersion.objects.create(rule=rule_lateral_auto_transfo, content=content)

    # Target Auto
    content = (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'
    )

    rule_target_auto_transfo = Rule.objects.create(sid=5, category=category, msg="test target auto => transfo")
    rule_target_auto_transfo.save()
    RuleAtVersion.objects.create(rule=rule_target_auto_transfo, content=content)

    content = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_CLIENT HTA File Download Flowbit Set"; \
flow:established,to_client; content:"Content-Type|3A| application/hta"; http_header; fast_pattern:12,16; flowbits:set,et.http.hta; \
flowbits:noalert; metadata: former_category WEB_CLIENT; classtype:not-suspicious; sid:2024195; rev:2; \
metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, \
signature_severity Major, created_at 2017_04_10, performance_impact Low, updated_at 2017_04_10;)'

    rule_target_auto_no_transfo = Rule.objects.create(sid=6, category=category, msg="test target auto => no transfo")
    rule_target_auto_no_transfo.save()
    RuleAtVersion.objects.create(rule=rule_target_auto_no_transfo, content=content)

    # Target Source
    content = (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'
    )

    rule_target_source_transfo = Rule.objects.create(sid=7, category=category, msg="test target source => transfo")
    rule_target_source_transfo.save()
    RuleAtVersion.objects.create(rule=rule_target_source_transfo, content=content)

    # Target Destination
    content = (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'
    )

    rule_target_destination_transfo = Rule.objects.create(
        sid=8, category=category, msg="test target destination => transfo"
    )
    rule_target_destination_transfo.save()
    RuleAtVersion.objects.create(rule=rule_target_destination_transfo, content=content)

    # Rule with existing target directive (for T_NONE test)
    content = (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET Test Rule With Target"; '
        'flow:established; content:"|00 01|"; classtype:trojan-activity; target:dest_ip; '
        "sid:9001; rev:1; metadata:affected_product Windows;)"
    )
    rule_with_target = Rule.objects.create(sid=9, category=category, msg="test rule with target directive")
    rule_with_target.save()
    RuleAtVersion.objects.create(rule=rule_with_target, content=content)

    return {
        "category": category,
        "source": source,
        "rule_commented": rule_commented,
        "rule_lateral_auto_no_transfo": rule_lateral_auto_no_transfo,
        "rule_lateral_auto_transfo": rule_lateral_auto_transfo,
        "rule_lateral_yes": rule_lateral_yes,
        "rule_target_auto_no_transfo": rule_target_auto_no_transfo,
        "rule_target_auto_transfo": rule_target_auto_transfo,
        "rule_target_destination_transfo": rule_target_destination_transfo,
        "rule_target_source_transfo": rule_target_source_transfo,
        "rule_with_target": rule_with_target,
    }


@pytest.mark.parametrize(
    "rule_key, transfo_key, transfo_value, check",
    [
        pytest.param(
            "rule_commented",
            Transformation.LATERAL,
            Transformation.L_YES,
            lambda orig, result: result == orig,
            id="commented-lateral-yes-unchanged",
        ),
        pytest.param(
            "rule_lateral_yes",
            Transformation.LATERAL,
            Transformation.L_YES,
            lambda _, result: "alert tcp any any" in result,
            id="lateral-yes",
        ),
        pytest.param(
            "rule_lateral_auto_no_transfo",
            Transformation.LATERAL,
            Transformation.L_AUTO,
            lambda orig, result: result == orig,
            id="lateral-auto-no-transfo",
        ),
        pytest.param(
            "rule_lateral_auto_transfo",
            Transformation.LATERAL,
            Transformation.L_AUTO,
            lambda _, result: "alert tcp any any" in result,
            id="lateral-auto-transfo",
        ),
        pytest.param(
            "rule_target_auto_transfo",
            Transformation.TARGET,
            Transformation.T_AUTO,
            lambda _, result: result.endswith("target:dest_ip;)"),
            id="target-auto-transfo",
        ),
        pytest.param(
            "rule_target_auto_no_transfo",
            Transformation.TARGET,
            Transformation.T_AUTO,
            lambda orig, result: result == orig,
            id="target-auto-no-transfo",
        ),
        pytest.param(
            "rule_target_source_transfo",
            Transformation.TARGET,
            Transformation.T_SOURCE,
            lambda _, result: result.endswith("target:src_ip;)"),
            id="target-source",
        ),
        pytest.param(
            "rule_target_destination_transfo",
            Transformation.TARGET,
            Transformation.T_DESTINATION,
            lambda _, result: result.endswith("target:dest_ip;)"),
            id="target-destination",
        ),
        pytest.param(
            "rule_lateral_yes",
            Transformation.LATERAL,
            Transformation.L_NO,
            lambda _, result: "$EXTERNAL_NET" in result,
            id="lateral-no-unchanged",
        ),
        pytest.param(
            "rule_with_target",
            Transformation.TARGET,
            Transformation.T_NONE,
            lambda _, result: "target:" not in result,
            id="target-none-removes-directive",
        ),
    ],
)
def test_transformation(setup_objects: TestData, rule_key: str, transfo_key, transfo_value, check: Callable):
    rule = setup_objects[rule_key]
    original = rule.ruleatversion_set.first().content
    result = rule.apply_lateral_target_transfo(original, transfo_key, transfo_value)
    assert check(original, result)


@pytest.mark.parametrize(
    "transfo_value, check",
    [
        pytest.param(Transformation.A_DROP, lambda _, result: result.startswith("drop "), id="action-drop"),
        pytest.param(Transformation.A_REJECT, lambda _, result: result.startswith("reject "), id="action-reject"),
        pytest.param(Transformation.A_FILESTORE, lambda _, result: "filestore;" in result, id="action-filestore"),
        pytest.param(
            Transformation.A_BYPASS,
            lambda _, result: result.startswith("pass ") and "bypass;" in result,
            id="action-bypass",
        ),
        pytest.param(Transformation.A_NONE, lambda orig, result: result == orig, id="action-none"),
    ],
)
def test_action_transformation(setup_objects: TestData, transfo_value, check: Callable):
    rule = setup_objects["rule_lateral_yes"]
    original = rule.ruleatversion_set.first().content
    result = rule.apply_transformation(original, Transformation.ACTION, transfo_value)
    assert check(original, result)


@pytest.fixture
def ruleset(db):
    source = Source.objects.create(name="test source", created_date=timezone.now(), method="local", datatype="sig")
    source.save()

    category = Category.objects.create(name="test category", filename="test", source=source)
    category.save()

    rule = Rule.objects.create(sid=1, category=category, msg="test rule")
    rule.save()

    ruleset = Ruleset.objects.create(
        name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
    )
    ruleset.save()
    ruleset.sources.add(source)
    ruleset.categories.add(category)
    return ruleset


@pytest.mark.parametrize(
    "transfo_type, values",
    [
        ("action", ("reject", "drop", "filestore")),
        ("lateral", ("yes", "auto", "yes")),
        ("target", ("src", "dst", "auto")),
    ],
)
def test_ruleset_transformations(drf: APIClient, ruleset: Ruleset, transfo_type: str, values: tuple[str, str, str]):
    post_value, patch_value, put_value = values

    # Create Ruleset Transformation
    params = {"ruleset": ruleset.pk, "transfo_type": transfo_type, "transfo_value": post_value}
    resp = drf.post(reverse("rulesettransformation-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED

    trans = RulesetTransformation.objects.filter(key=transfo_type)
    assert trans.count() == 1
    assert trans[0].ruleset_transformation == ruleset
    assert trans[0].key == transfo_type
    assert trans[0].value == post_value
    pk = trans[0].pk

    # PATCH Ruleset Transformation
    params = {"ruleset": ruleset.pk, "transfo_type": transfo_type, "transfo_value": patch_value}
    resp = drf.patch(reverse("rulesettransformation-detail", args=(pk,)), params)
    assert resp.status_code == status.HTTP_200_OK

    trans = RulesetTransformation.objects.filter(key=transfo_type)
    assert trans[0].ruleset_transformation == ruleset
    assert trans[0].key == transfo_type
    assert trans[0].value == patch_value

    # PUT Ruleset Transformation
    params = {"ruleset": ruleset.pk, "transfo_type": transfo_type, "transfo_value": put_value}
    resp = drf.put(reverse("rulesettransformation-detail", args=(pk,)), params)
    assert resp.status_code == status.HTTP_200_OK

    trans = RulesetTransformation.objects.filter(key=transfo_type)
    assert trans[0].ruleset_transformation == ruleset
    assert trans[0].key == transfo_type
    assert trans[0].value == put_value

    # Delete
    resp = drf.delete(reverse("rulesettransformation-detail", args=(pk,)))
    assert resp.status_code == status.HTTP_204_NO_CONTENT
    assert RulesetTransformation.objects.count() == 0


@pytest.fixture
def ruleset_with_rule(db):
    """Ruleset with a rule that has content supporting action/lateral/target transformations."""
    source = Source.objects.create(name="transfo source", created_date=timezone.now(), method="local", datatype="sig")
    category = Category.objects.create(name="transfo category", filename="transfo", source=source)
    content = (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET Test Transfo"; '
        'flow:established; content:"|00 01|"; classtype:trojan-activity; sid:9999; rev:1;)'
    )
    rule = Rule.objects.create(sid=9999, category=category, msg="test transfo rule")
    RuleAtVersion.objects.create(rule=rule, content=content)
    rs = Ruleset.objects.create(
        name="transfo ruleset", descr="", created_date=timezone.now(), updated_date=timezone.now()
    )
    rs.sources.add(source)
    rs.categories.add(category)
    return {"ruleset": rs, "category": category, "rule": rule}


@pytest.mark.parametrize(
    "transfo_type, values",
    [
        ("action", ("reject", "drop", "filestore")),
        ("lateral", ("yes", "auto", "yes")),
        ("target", ("src", "dst", "auto")),
    ],
)
def test_category_transformations(drf: APIClient, ruleset: Ruleset, transfo_type: str, values: tuple[str, str, str]):
    category = ruleset.categories.first()
    assert category is not None
    post_value, patch_value, put_value = values

    # Create
    params = {"category": category.pk, "ruleset": ruleset.pk, "transfo_type": transfo_type, "transfo_value": post_value}
    resp = drf.post(reverse("categorytransformation-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED

    trans = CategoryTransformation.objects.filter(key=transfo_type)
    assert trans.count() == 1
    assert trans[0].category_transformation == category
    assert trans[0].key == transfo_type
    assert trans[0].value == post_value
    pk = trans[0].pk

    # PATCH
    params = {
        "category": category.pk,
        "ruleset": ruleset.pk,
        "transfo_type": transfo_type,
        "transfo_value": patch_value,
    }
    resp = drf.patch(reverse("categorytransformation-detail", args=(pk,)), params)
    assert resp.status_code == status.HTTP_200_OK

    trans = CategoryTransformation.objects.filter(key=transfo_type)
    assert trans[0].category_transformation == category
    assert trans[0].key == transfo_type
    assert trans[0].value == patch_value

    # PUT
    params = {"category": category.pk, "ruleset": ruleset.pk, "transfo_type": transfo_type, "transfo_value": put_value}
    resp = drf.put(reverse("categorytransformation-detail", args=(pk,)), params)
    assert resp.status_code == status.HTTP_200_OK

    trans = CategoryTransformation.objects.filter(key=transfo_type)
    assert trans[0].category_transformation == category
    assert trans[0].key == transfo_type
    assert trans[0].value == put_value

    # Delete
    resp = drf.delete(reverse("categorytransformation-detail", args=(pk,)))
    assert resp.status_code == status.HTTP_204_NO_CONTENT
    assert CategoryTransformation.objects.count() == 0


@pytest.mark.parametrize(
    "transfo_type, values",
    [
        ("action", ("reject", "drop", "bypass")),
        ("lateral", ("yes", "auto", "no")),
        ("target", ("src", "dst", "auto")),
    ],
)
def test_rule_transformations(drf: APIClient, ruleset_with_rule: dict, transfo_type: str, values: tuple[str, str, str]):
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    post_value, patch_value, put_value = values

    # Create
    params = {"rule": rule.pk, "ruleset": rs.pk, "transfo_type": transfo_type, "transfo_value": post_value}
    resp = drf.post(reverse("ruletransformation-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED

    trans = RuleTransformation.objects.filter(key=transfo_type)
    assert trans.count() == 1
    assert trans[0].rule_transformation == rule
    assert trans[0].key == transfo_type
    assert trans[0].value == post_value
    pk = trans[0].pk

    # PATCH
    params = {"rule": rule.pk, "ruleset": rs.pk, "transfo_type": transfo_type, "transfo_value": patch_value}
    resp = drf.patch(reverse("ruletransformation-detail", args=(pk,)), params)
    assert resp.status_code == status.HTTP_200_OK

    trans = RuleTransformation.objects.filter(key=transfo_type)
    assert trans[0].rule_transformation == rule
    assert trans[0].key == transfo_type
    assert trans[0].value == patch_value

    # PUT
    params = {"rule": rule.pk, "ruleset": rs.pk, "transfo_type": transfo_type, "transfo_value": put_value}
    resp = drf.put(reverse("ruletransformation-detail", args=(pk,)), params)
    assert resp.status_code == status.HTTP_200_OK

    trans = RuleTransformation.objects.filter(key=transfo_type)
    assert trans[0].rule_transformation == rule
    assert trans[0].key == transfo_type
    assert trans[0].value == put_value

    # Delete
    resp = drf.delete(reverse("ruletransformation-detail", args=(pk,)))
    assert resp.status_code == status.HTTP_204_NO_CONTENT
    assert RuleTransformation.objects.count() == 0


def test_rule_transformation_create_rejects_invalid_rule_choice(drf: APIClient, ruleset_with_rule: dict):
    """POSTing a transfo_value that is not a valid choice for the specific rule returns 400.

    The fixture rule uses protocol 'tcp', so can_filestore() is False and 'filestore' is
    excluded from its ACTION choices by get_transformation_choices().
    """
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    params = {"rule": rule.pk, "ruleset": rs.pk, "transfo_type": "action", "transfo_value": "filestore"}
    resp = drf.post(reverse("ruletransformation-list"), params)
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.parametrize(
    "query_string, expected_error_key",
    [
        pytest.param("?transfo_value=drop", "transfo_type", id="missing-transfo-type"),
        pytest.param("?transfo_type=action", "transfo_value", id="missing-transfo-value"),
        pytest.param("", None, id="both-missing"),
        pytest.param("?transfo_type=action&transfo_value=drop&unknown=foo", "filters", id="extra-filter"),
        pytest.param("?transfo_type=bad_type&transfo_value=drop", "filters", id="wrong-transfo-type"),
        pytest.param("?transfo_type=action&transfo_value=bad_value", "filters", id="wrong-transfo-value"),
    ],
)
def test_rule_transformation_endpoint_invalid_request(
    drf: APIClient, query_string: str, expected_error_key: str | None
):
    resp = drf.get(reverse("rule-transformation") + query_string)
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    if expected_error_key is not None:
        assert expected_error_key in resp.json()


def test_rule_transformation_endpoint_category_level(drf: APIClient, ruleset: Ruleset):
    category = ruleset.categories.first()
    assert category is not None

    drf.post(
        reverse("categorytransformation-list"),
        {"category": category.pk, "ruleset": ruleset.pk, "transfo_type": "action", "transfo_value": "reject"},
    )

    resp = drf.get(reverse("rule-transformation") + "?transfo_type=action&transfo_value=reject")
    assert resp.status_code == status.HTTP_200_OK

    content = resp.json()
    assert str(ruleset.pk) in content
    assert content[str(ruleset.pk)]["transformation"]["transfo_key"] == "action"
    assert content[str(ruleset.pk)]["transformation"]["transfo_value"] == "reject"
    rule = Rule.objects.filter(category=category).first()
    assert rule is not None
    assert rule.sid in content[str(ruleset.pk)]["rules"]


def test_rule_transformation_endpoint_ruleset_level(drf: APIClient, ruleset: Ruleset):
    drf.post(
        reverse("rulesettransformation-list"),
        {"ruleset": ruleset.pk, "transfo_type": "action", "transfo_value": "drop"},
    )

    resp = drf.get(reverse("rule-transformation") + "?transfo_type=action&transfo_value=drop")
    assert resp.status_code == status.HTTP_200_OK

    content = resp.json()
    assert str(ruleset.pk) in content
    assert content[str(ruleset.pk)]["transformation"]["transfo_key"] == "action"
    assert content[str(ruleset.pk)]["transformation"]["transfo_value"] == "drop"
    first_category = ruleset.categories.first()
    assert first_category is not None
    first_rule = Rule.objects.filter(category=first_category).first()
    assert first_rule is not None
    assert first_rule.sid in content[str(ruleset.pk)]["rules"]


# ============ Category model method tests ============


@pytest.mark.parametrize(
    "transfo_key, transfo_value, expected",
    [
        pytest.param(Transformation.ACTION, Transformation.A_DROP, Transformation.A_DROP, id="action-drop"),
        pytest.param(Transformation.LATERAL, Transformation.L_YES, Transformation.L_YES, id="lateral-yes"),
        pytest.param(Transformation.TARGET, Transformation.T_SOURCE, Transformation.T_SOURCE, id="target-src"),
    ],
)
def test_category_get_transformation_direct(ruleset_with_rule: dict, transfo_key, transfo_value, expected):
    rs = ruleset_with_rule["ruleset"]
    category = ruleset_with_rule["category"]
    CategoryTransformation.objects.create(
        ruleset=rs, category_transformation=category, key=transfo_key.value, value=transfo_value.value
    )
    assert TransformationService().get_for_category(category, rs, transfo_key) == expected


def test_category_get_transformation_none_when_no_transfo(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    category = ruleset_with_rule["category"]
    assert TransformationService().get_for_category(category, rs, Transformation.ACTION) is None


def test_category_get_transformation_override_from_ruleset(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    category = ruleset_with_rule["category"]
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_REJECT.value
    )
    # No CategoryTransformation; override=True falls back to the ruleset value
    assert (
        TransformationService().get_for_category(category, rs, Transformation.ACTION, override=True)
        == Transformation.A_REJECT
    )


def test_category_get_transformation_no_override_ignores_ruleset(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    category = ruleset_with_rule["category"]
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_REJECT.value
    )
    # override=False: ruleset value not consulted
    assert TransformationService().get_for_category(category, rs, Transformation.ACTION, override=False) is None


def test_category_get_transformation_direct_wins_over_ruleset(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    category = ruleset_with_rule["category"]
    CategoryTransformation.objects.create(
        ruleset=rs, category_transformation=category, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_REJECT.value
    )
    # Category-level takes priority even with override=True
    assert (
        TransformationService().get_for_category(category, rs, Transformation.ACTION, override=True)
        == Transformation.A_DROP
    )


def test_category_get_transformation_invalid_key(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    category = ruleset_with_rule["category"]
    with pytest.raises(Exception, match="is unknown"):
        TransformationService().get_for_category(category, rs, "bad_key")  # type: ignore[arg-type]


def test_category_is_transformed_true(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    category = ruleset_with_rule["category"]
    CategoryTransformation.objects.create(
        ruleset=rs, category_transformation=category, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    assert TransformationService().is_transformed(category, rs, key=Transformation.ACTION, value=Transformation.A_DROP)


def test_category_is_transformed_false_no_transfo(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    category = ruleset_with_rule["category"]
    assert not TransformationService().is_transformed(
        category, rs, key=Transformation.ACTION, value=Transformation.A_DROP
    )


def test_category_is_transformed_false_different_value(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    category = ruleset_with_rule["category"]
    CategoryTransformation.objects.create(
        ruleset=rs,
        category_transformation=category,
        key=Transformation.ACTION.value,
        value=Transformation.A_REJECT.value,
    )
    # Transformation exists but with different value
    assert not TransformationService().is_transformed(
        category, rs, key=Transformation.ACTION, value=Transformation.A_DROP
    )


# ============ Rule model method tests ============


@pytest.mark.parametrize(
    "transfo_key, transfo_value, expected",
    [
        pytest.param(Transformation.ACTION, Transformation.A_REJECT, Transformation.A_REJECT, id="action-reject"),
        pytest.param(Transformation.LATERAL, Transformation.L_YES, Transformation.L_YES, id="lateral-yes"),
        pytest.param(Transformation.TARGET, Transformation.T_SOURCE, Transformation.T_SOURCE, id="target-src"),
    ],
)
def test_rule_get_transformation_direct(ruleset_with_rule: dict, transfo_key, transfo_value, expected):
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    RuleTransformation.objects.create(
        ruleset=rs, rule_transformation=rule, key=transfo_key.value, value=transfo_value.value
    )
    assert TransformationService().get_for_rule(rule, rs, transfo_key) == expected


def test_rule_get_transformation_none_when_no_transfo(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    assert TransformationService().get_for_rule(rule, rs, Transformation.ACTION) is None


def test_rule_get_transformation_override_category(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    category = ruleset_with_rule["category"]
    CategoryTransformation.objects.create(
        ruleset=rs, category_transformation=category, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    # No rule-level; override=True falls back to category value
    assert TransformationService().get_for_rule(rule, rs, Transformation.ACTION, override=True) == Transformation.A_DROP


def test_rule_get_transformation_override_ruleset(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_BYPASS.value
    )
    # No rule or category transfo; override=True falls back to ruleset value
    assert (
        TransformationService().get_for_rule(rule, rs, Transformation.ACTION, override=True) == Transformation.A_BYPASS
    )


def test_rule_get_transformation_rule_wins_over_category(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    category = ruleset_with_rule["category"]
    CategoryTransformation.objects.create(
        ruleset=rs, category_transformation=category, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    RuleTransformation.objects.create(
        ruleset=rs, rule_transformation=rule, key=Transformation.ACTION.value, value=Transformation.A_REJECT.value
    )
    assert (
        TransformationService().get_for_rule(rule, rs, Transformation.ACTION, override=True) == Transformation.A_REJECT
    )


def test_rule_get_transformation_no_override_ignores_category(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    category = ruleset_with_rule["category"]
    CategoryTransformation.objects.create(
        ruleset=rs, category_transformation=category, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    # override=False: only rule-level check; category not consulted
    assert TransformationService().get_for_rule(rule, rs, Transformation.ACTION, override=False) is None


def test_rule_get_transformation_invalid_key(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    with pytest.raises(Exception, match="is unknown"):
        TransformationService().get_for_rule(rule, rs, "bad_key")  # type: ignore[arg-type]


def test_rule_is_transformed_false_no_transfo(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    assert not TransformationService().is_transformed(rule, rs, key=Transformation.ACTION, value=Transformation.A_DROP)


def test_rule_is_transformed_true(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    RuleTransformation.objects.create(
        ruleset=rs, rule_transformation=rule, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    assert TransformationService().is_transformed(rule, rs, key=Transformation.ACTION, value=Transformation.A_DROP)


# ============ Ruleset model method tests ============


@pytest.mark.parametrize(
    "transfo_key, transfo_value, expected",
    [
        pytest.param(Transformation.ACTION, Transformation.A_DROP, Transformation.A_DROP, id="action-drop"),
        pytest.param(Transformation.LATERAL, Transformation.L_YES, Transformation.L_YES, id="lateral-yes"),
        pytest.param(Transformation.TARGET, Transformation.T_SOURCE, Transformation.T_SOURCE, id="target-src"),
    ],
)
def test_ruleset_get_transformation_direct(ruleset_with_rule: dict, transfo_key, transfo_value, expected):
    rs = ruleset_with_rule["ruleset"]
    RulesetTransformation.objects.create(ruleset_transformation=rs, key=transfo_key.value, value=transfo_value.value)
    assert TransformationService().get_for_ruleset(rs, transfo_key) == expected


def test_ruleset_get_transformation_none_when_no_transfo(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    assert TransformationService().get_for_ruleset(rs, Transformation.ACTION) is None


def test_ruleset_get_transformation_excludes_action_none(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    # "none" action value is excluded from the query
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_NONE.value
    )
    assert TransformationService().get_for_ruleset(rs, Transformation.ACTION) is None


def test_ruleset_get_transformation_excludes_lateral_no(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    # "no" is the NONE equivalent for lateral and is excluded
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.LATERAL.value, value=Transformation.L_NO.value
    )
    assert TransformationService().get_for_ruleset(rs, Transformation.LATERAL) is None


def test_ruleset_get_transformation_excludes_target_none(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.TARGET.value, value=Transformation.T_NONE.value
    )
    assert TransformationService().get_for_ruleset(rs, Transformation.TARGET) is None


def test_ruleset_get_transformation_invalid_key(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    with pytest.raises(Exception, match="is unknown"):
        TransformationService().get_for_ruleset(rs, "bad_key")  # type: ignore[arg-type]


def test_ruleset_is_transformed_true(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    assert TransformationService().is_transformed(rs, None, key=Transformation.ACTION, value=Transformation.A_DROP)


def test_ruleset_is_transformed_false_no_transfo(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    assert not TransformationService().is_transformed(rs, None, key=Transformation.ACTION, value=Transformation.A_DROP)


def test_ruleset_is_transformed_false_different_value(ruleset_with_rule: dict):
    rs = ruleset_with_rule["ruleset"]
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_REJECT.value
    )
    assert not TransformationService().is_transformed(rs, None, key=Transformation.ACTION, value=Transformation.A_DROP)


# ============ get_transformed_rules (ruleset-level inheritance) ============


@pytest.fixture
def multi_category_ruleset(db):
    """Ruleset with two categories, one rule each — no transformations."""
    source = Source.objects.create(name="mc source", created_date=timezone.now(), method="local", datatype="sig")
    cat_a = Category.objects.create(name="cat-a", filename="cat_a.rules", source=source)
    cat_b = Category.objects.create(name="cat-b", filename="cat_b.rules", source=source)
    rule_a = Rule.objects.create(sid=2001, category=cat_a, msg="rule a")
    rule_b = Rule.objects.create(sid=2002, category=cat_b, msg="rule b")
    rs = Ruleset.objects.create(
        name="mc ruleset", descr="", created_date=timezone.now(), updated_date=timezone.now()
    )
    rs.sources.add(source)
    rs.categories.add(cat_a, cat_b)
    return {"ruleset": rs, "cat_a": cat_a, "cat_b": cat_b, "rule_a": rule_a, "rule_b": rule_b}


def test_get_transformed_rules_empty_when_no_ruleset_transfo(ruleset_with_rule: dict):
    """No RulesetTransformation → early return, no rules in result."""
    rs = ruleset_with_rule["ruleset"]
    result = TransformationService().get_transformed_rules("action", "drop")
    assert result[rs.pk]["rules"] == []


def test_get_transformed_rules_ruleset_level_includes_rule(ruleset_with_rule: dict):
    """RulesetTransformation with no category/rule overrides → rule is included."""
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    result = TransformationService().get_transformed_rules("action", "drop")
    assert rule.sid in result[rs.pk]["rules"]


def test_get_transformed_rules_ruleset_level_excludes_rule_with_different_rule_transfo(ruleset_with_rule: dict):
    """Rule-level transformation with a different value overrides the ruleset → rule excluded."""
    rs = ruleset_with_rule["ruleset"]
    rule = ruleset_with_rule["rule"]
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    RuleTransformation.objects.create(
        ruleset=rs, rule_transformation=rule, key=Transformation.ACTION.value, value=Transformation.A_REJECT.value
    )
    result = TransformationService().get_transformed_rules("action", "drop")
    assert rule.sid not in result[rs.pk]["rules"]


def test_get_transformed_rules_ruleset_level_multi_category(multi_category_ruleset: dict):
    """Ruleset transformation with two unconfigured categories → both rules included."""
    rs = multi_category_ruleset["ruleset"]
    rule_a = multi_category_ruleset["rule_a"]
    rule_b = multi_category_ruleset["rule_b"]
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    result = TransformationService().get_transformed_rules("action", "drop")
    rules = result[rs.pk]["rules"]
    assert rule_a.sid in rules
    assert rule_b.sid in rules


def test_get_transformed_rules_category_transfo_does_not_block_ruleset_cascade(multi_category_ruleset: dict):
    """A CategoryTransformation with a different value does not exclude rules from the ruleset-level
    result — only an explicit rule-level override with a conflicting value does."""
    rs = multi_category_ruleset["ruleset"]
    cat_b = multi_category_ruleset["cat_b"]
    rule_a = multi_category_ruleset["rule_a"]
    rule_b = multi_category_ruleset["rule_b"]
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    # cat_b has a category-level reject — but no rule-level override, so rule_b still inherits
    # the ruleset-level drop via the else branch in _rules_from_ruleset_transformations.
    CategoryTransformation.objects.create(
        ruleset=rs,
        category_transformation=cat_b,
        key=Transformation.ACTION.value,
        value=Transformation.A_REJECT.value,
    )
    result = TransformationService().get_transformed_rules("action", "drop")
    rules = result[rs.pk]["rules"]
    assert rule_a.sid in rules
    assert rule_b.sid in rules  # no rule-level override → included


def test_get_transformed_rules_rule_override_excludes_in_multi_category(multi_category_ruleset: dict):
    """An explicit rule-level transformation with a different value is the correct way to exclude a rule."""
    rs = multi_category_ruleset["ruleset"]
    rule_a = multi_category_ruleset["rule_a"]
    rule_b = multi_category_ruleset["rule_b"]
    RulesetTransformation.objects.create(
        ruleset_transformation=rs, key=Transformation.ACTION.value, value=Transformation.A_DROP.value
    )
    RuleTransformation.objects.create(
        ruleset=rs, rule_transformation=rule_b, key=Transformation.ACTION.value, value=Transformation.A_REJECT.value
    )
    result = TransformationService().get_transformed_rules("action", "drop")
    rules = result[rs.pk]["rules"]
    assert rule_a.sid in rules
    assert rule_b.sid not in rules  # rule-level reject overrides the ruleset-level drop
