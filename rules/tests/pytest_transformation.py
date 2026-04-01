from collections.abc import Callable
from typing import TypedDict
import pytest

from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from rules.models.model import (
    Category,
    Rule,
    RuleAtVersion,
    Ruleset,
    RulesetTransformation,
    Source,
    Transformation,
)


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
