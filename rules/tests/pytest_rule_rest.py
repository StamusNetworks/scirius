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
    Source,
    SuppressedRuleAtVersion,
    Transformation,
    RuleTransformation,
    UserAction,
)
from rules.services.transformation import TransformationService


@pytest.fixture
def source(db):
    source = Source.objects.create(name="test source", created_date=timezone.now(), method="local", datatype="sig")
    source.save()
    return source


@pytest.fixture
def category(source):
    category = Category.objects.create(name="test category", filename="test", source=source)
    category.save()
    return category


@pytest.fixture
def rule(category):
    content = (
        'alert ip $HOME_NET any -> [103.207.29.161,103.207.29.171,103.225.168.222,103.234.36.190,103.234.37.4,103.4.164.34, \
103.6.207.37,104.131.93.109,104.140.137.152,104.143.5.144,104.144.167.131,104.144.167.251,104.194.206.108, \
104.199.121.36,104.207.154.26,104.223.87.207,104.43.200.222,106.187.48.236,107.161.19.71] \
any (msg:"ET CNC Shadowserver Reported CnC Server IP group 1"; \
reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,www.shadowserver.org;\
threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; \
flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404000; rev:4933;)'
    )

    rule = Rule.objects.create(sid=1, category=category, msg="test rule")
    rule.save()
    RuleAtVersion.objects.create(rule=rule, content=content)
    return rule


@pytest.fixture
def ruleset(source, category):
    ruleset = Ruleset.objects.create(
        name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
    )
    ruleset.save()
    ruleset.sources.add(source)
    ruleset.categories.add(category)
    return ruleset


def test_001_rule_detail(drf: APIClient, rule):
    resp = drf.get(reverse("rule-detail", args=(rule.pk,)))
    assert resp.status_code == status.HTTP_200_OK


def test_002_rule_disable(drf: APIClient, ruleset, rule):
    nb_items = SuppressedRuleAtVersion.objects.filter(
        ruleset=ruleset, rule_at_version=rule.ruleatversion_set.first()
    ).count()
    assert nb_items == 0

    resp = drf.post(reverse("rule-disable", args=(rule.pk,)), {"ruleset": ruleset.pk})
    ruleset.refresh_from_db()

    nb_items = SuppressedRuleAtVersion.objects.filter(
        ruleset=ruleset, rule_at_version=rule.ruleatversion_set.first()
    ).count()
    item = SuppressedRuleAtVersion.objects.filter(
        ruleset=ruleset, rule_at_version=rule.ruleatversion_set.first()
    ).first()
    assert nb_items == 1
    assert item.rule_at_version.pk == rule.ruleatversion_set.first().pk
    assert item.rule_at_version.rule.pk == rule.pk

    resp = drf.post(reverse("rule-enable", args=(rule.pk,)), {"ruleset": ruleset.pk})
    assert resp.status_code == status.HTTP_200_OK
    ruleset.refresh_from_db()

    nb_items = SuppressedRuleAtVersion.objects.filter(
        ruleset=ruleset, rule_at_version=rule.ruleatversion_set.first()
    ).count()
    assert nb_items == 0


def test_004_rule_transformation(drf: APIClient, ruleset, category, rule):
    # Transform ruleset
    resp = drf.post(
        reverse("rulesettransformation-list"),
        {
            "ruleset": ruleset.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_FILESTORE.value,
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED

    service = TransformationService()

    # Check inheritance on category
    transformation = service.get_for_category(category, ruleset, Transformation.ACTION, override=True)
    assert transformation == Transformation.A_FILESTORE

    # Check inheritance on rule
    transformation = service.get_for_rule(rule, ruleset, Transformation.ACTION, override=True)
    assert transformation == Transformation.A_FILESTORE

    # Transform Category
    resp = drf.post(
        reverse("categorytransformation-list"),
        {
            "category": category.pk,
            "ruleset": ruleset.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_DROP.value,
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED

    # Check category transformation
    transformation = service.get_for_category(category, ruleset, Transformation.ACTION)
    assert transformation == Transformation.A_DROP

    # Check inheritance on rule (from category)
    transformation = service.get_for_rule(rule, ruleset, Transformation.ACTION, override=True)
    assert transformation == Transformation.A_DROP

    # Transform rule
    resp = drf.post(
        reverse("ruletransformation-list"),
        {
            "rule": rule.pk,
            "ruleset": ruleset.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_REJECT.value,
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED

    # Check transformed rule
    transformed = ruleset.get_transformed_rules(key=Transformation.ACTION, value=Transformation.A_REJECT)
    assert transformed.count() == 1
    assert transformed[0].pk == rule.pk

    transformation = service.get_for_rule(rule, ruleset, Transformation.ACTION)
    assert transformation == Transformation.A_REJECT

    # Transform same rule
    ruletransformation = RuleTransformation.objects.filter(rule_transformation=rule, ruleset=ruleset)
    resp = drf.patch(
        reverse("ruletransformation-detail", args=(ruletransformation[0].pk,)),
        {
            "rule": rule.pk,
            "ruleset": ruleset.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_DROP.value,
        },
    )

    transformed = ruleset.get_transformed_rules(key=Transformation.ACTION, value=Transformation.A_REJECT)
    assert transformed.count() == 0


def test_005_rule_transformation_content(drf: APIClient, ruleset, category, rule):
    version = 0
    resp = drf.post(
        reverse("rulesettransformation-list"),
        {
            "ruleset": ruleset.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_DROP.value,
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED

    resp = drf.get(reverse("rule-content", args=(rule.pk,)))
    assert resp.status_code == status.HTTP_200_OK
    content = resp.json()
    assert "drop" in content[str(ruleset.pk)][str(version)]

    resp = drf.post(
        reverse("categorytransformation-list"),
        {
            "category": category.pk,
            "ruleset": ruleset.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_REJECT.value,
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED

    resp = drf.get(reverse("rule-content", args=(rule.pk,)))
    assert resp.status_code == status.HTTP_200_OK
    content = resp.json()
    assert "reject" in content[str(ruleset.pk)][str(version)]

    resp = drf.post(
        reverse("ruletransformation-list"),
        {
            "rule": rule.pk,
            "ruleset": ruleset.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_DROP.value,
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED

    resp = drf.get(reverse("rule-content", args=(rule.pk,)))
    assert resp.status_code == status.HTTP_200_OK
    content = resp.json()
    assert "drop" in content[str(ruleset.pk)][str(version)]


def test_006_rule_status(drf: APIClient, ruleset, category, rule):
    resp = drf.post(
        reverse("rulesettransformation-list"),
        {
            "ruleset": ruleset.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_DROP.value,
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED

    resp = drf.get(reverse("rule-status", args=(rule.pk,)))
    assert resp.status_code == status.HTTP_200_OK
    status_ = resp.json()
    assert str(ruleset.pk) in status_
    assert status_[str(ruleset.pk)]["transformations"]["action"] == "drop"

    resp = drf.post(
        reverse("categorytransformation-list"),
        {
            "category": category.pk,
            "ruleset": ruleset.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_REJECT.value,
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED

    resp = drf.get(reverse("rule-status", args=(rule.pk,)))
    assert resp.status_code == status.HTTP_200_OK
    status_ = resp.json()
    assert str(ruleset.pk) in status_
    assert status_[str(ruleset.pk)]["transformations"]["action"] == "reject"


def test_007_rule_toggle_availability(drf: APIClient, rule):
    resp = drf.post(reverse("rule-toggle-availability", args=(rule.pk,)), {})
    assert resp.status_code == status.HTTP_200_OK
    rule = Rule.objects.get(pk=rule.pk)
    for rav in rule.ruleatversion_set.all():
        assert not rav.state

    resp = drf.post(reverse("rule-toggle-availability", args=(rule.pk,)), {})
    assert resp.status_code == status.HTTP_200_OK
    rule = Rule.objects.get(pk=rule.pk)
    for rav in rule.ruleatversion_set.all():
        assert rav.state


def test_008_rule_comment(drf: APIClient, rule):
    comment = "Need a comment for my test."
    resp = drf.post(reverse("rule-comment", args=(rule.pk,)), {"comment": comment})
    assert resp.status_code == status.HTTP_200_OK

    ua = UserAction.objects.order_by("pk").last()
    assert ua.comment == comment


def test_009_get_transformed_rules(drf: APIClient, ruleset, category, rule):
    # Transform ruleset
    resp = drf.post(
        reverse("rulesettransformation-list"),
        {
            "ruleset": ruleset.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_REJECT.value,
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED
    params = f"?transfo_type={Transformation.ACTION.value}&transfo_value={Transformation.A_REJECT.value}"
    resp = drf.get(reverse("rule-transformation") + params)
    assert resp.status_code == status.HTTP_200_OK
    content = resp.json()

    assert str(ruleset.pk) in content
    assert content[str(ruleset.pk)]["rules"][0] == rule.pk
    assert content[str(ruleset.pk)]["transformation"]["transfo_key"] == Transformation.ACTION.value
    assert content[str(ruleset.pk)]["transformation"]["transfo_value"] == Transformation.A_REJECT.value

    resp = drf.post(
        reverse("categorytransformation-list"),
        {
            "ruleset": ruleset.pk,
            "category": category.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_DROP.value,
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED
    params = f"?transfo_type={Transformation.ACTION.value}&transfo_value={Transformation.A_DROP.value}"
    resp = drf.get(reverse("rule-transformation") + params)
    assert resp.status_code == status.HTTP_200_OK
    content = resp.json()

    assert str(ruleset.pk) in content
    assert content[str(ruleset.pk)]["rules"][0] == rule.pk
    assert content[str(ruleset.pk)]["transformation"]["transfo_key"] == Transformation.ACTION.value
    assert content[str(ruleset.pk)]["transformation"]["transfo_value"] == Transformation.A_DROP.value

    resp = drf.post(
        reverse("ruletransformation-list"),
        {
            "ruleset": ruleset.pk,
            "rule": rule.pk,
            "transfo_type": Transformation.ACTION.value,
            "transfo_value": Transformation.A_BYPASS.value,
        },
    )
    assert resp.status_code == status.HTTP_201_CREATED
    assert str(ruleset.pk) in content
    params = f"?transfo_type={Transformation.ACTION.value}&transfo_value={Transformation.A_BYPASS.value}"
    resp = drf.get(reverse("rule-transformation") + params)
    assert resp.status_code == status.HTTP_200_OK
    content = resp.json()

    assert str(ruleset.pk) in content
    assert content[str(ruleset.pk)]["rules"][0] == rule.pk
    assert content[str(ruleset.pk)]["transformation"]["transfo_key"] == Transformation.ACTION.value
    assert content[str(ruleset.pk)]["transformation"]["transfo_value"] == Transformation.A_BYPASS.value
