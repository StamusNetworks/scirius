import pytest

from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from rules.models.model import Category, Rule, Ruleset, Source


@pytest.fixture
def source(db):
    source = Source.objects.create(name="test source", created_date=timezone.now(), method="local", datatype="sig")
    source.save()
    return source


@pytest.fixture
def source2(db):
    source = Source.objects.create(name="test source 2", created_date=timezone.now(), method="local", datatype="sig")
    source.save()
    return source


@pytest.fixture
def category(source):
    category = Category.objects.create(name="test category", filename="test", source=source)
    category.save()
    return category


@pytest.fixture
def rule(category):
    rule = Rule.objects.create(sid=1, category=category, msg="test rule")
    rule.save()
    return rule


def test_001_ruleset_actions(drf: APIClient, source, source2, category):
    params = {
        "name": "MyCreatedRuleset",
        "comment": "My custom ruleset comment",
        "sources": [source.pk, source2.pk],
        "categories": [category.pk],
    }

    # Create Ruleset
    resp = drf.post(reverse("ruleset-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED
    rulesets = Ruleset.objects.all()
    sources = rulesets[0].sources.all()

    assert rulesets.count() == 1
    assert rulesets[0].name == "MyCreatedRuleset"
    assert rulesets[0].categories.count() > 0
    assert sources.count() == 2

    for src in sources:
        assert src in [source, source2]

    # PUT/PATCH Ruleset
    for idx, request in enumerate((drf.put, drf.patch)):
        params["name"] = f"MyRenamedCreatedRuleset{idx}"

        status_ = status.HTTP_200_OK
        if request == drf.patch:
            params["sources"] = []
            status_ = status.HTTP_400_BAD_REQUEST

        resp = request(reverse("ruleset-detail", args=(rulesets[0].pk,)), params)
        assert resp.status_code == status_

        if request == drf.patch:
            del params["sources"]

        resp = request(reverse("ruleset-detail", args=(rulesets[0].pk,)), params)
        assert resp.status_code == status.HTTP_200_OK

        rulesets = Ruleset.objects.all()
        assert rulesets.count() == 1
        assert rulesets[0].name == f"MyRenamedCreatedRuleset{idx}"

        assert rulesets[0].sources.count() == 2

    # Delete
    rulesets = Ruleset.objects.all()
    assert rulesets.count() == 1
    resp = drf.delete(reverse("ruleset-detail", args=(rulesets[0].pk,)))
    assert resp.status_code == status.HTTP_204_NO_CONTENT
    rulesets = Ruleset.objects.all()
    assert rulesets.count() == 0


def test_002_create_ruleset_source_wrong_category(drf: APIClient, source2, category):
    params = {
        "name": "MyCreatedRuleset",
        "comment": "My custom ruleset comment",
        "sources": [source2.pk],
        "categories": [category.pk],
    }
    resp = drf.post(reverse("ruleset-list"), params)
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


def test_003_create_ruleset_no_source_categories(drf: APIClient, category):
    params = {"name": "MyCreatedRuleset", "comment": "My custom ruleset comment", "categories": [category.pk]}
    resp = drf.post(reverse("ruleset-list"), params)
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


def test_004_create_ruleset_sources_categories(drf: APIClient, source, category):
    params = {
        "name": "MyCreatedRuleset",
        "comment": "My custom ruleset comment",
        "sources": [source.pk],
        "categories": [category.pk],
    }
    resp = drf.post(reverse("ruleset-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED


def test_005_update_ruleset_source_wrong_category(drf: APIClient, source, source2, category):
    params = {
        "name": "MyCreatedRuleset",
        "comment": "My custom ruleset comment",
        "sources": [source.pk],
        "categories": [category.pk],
    }

    # Create valid Ruleset
    resp = drf.post(reverse("ruleset-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED
    rulesets = Ruleset.objects.all()
    assert rulesets.count() == 1

    # PUT/PATCH
    params["sources"] = [source2.pk]
    for idx, request in enumerate((drf.put, drf.patch)):
        params["name"] = f"MyRenamedCreatedRuleset{idx}"
        resp = request(reverse("ruleset-detail", args=(rulesets[0].pk,)), params)
        assert resp.status_code == status.HTTP_400_BAD_REQUEST


def test_006_update_ruleset_no_source_categories(drf: APIClient, source, category):
    params = {
        "name": "MyCreatedRuleset",
        "comment": "My custom ruleset comment",
        "sources": [source.pk],
        "categories": [category.pk],
    }

    # Create valid Ruleset
    resp = drf.post(reverse("ruleset-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED
    rulesets = Ruleset.objects.all()
    assert rulesets.count() == 1

    # PUT/PATCH
    params.pop("sources")
    for idx, request in enumerate((drf.put, drf.patch)):
        params["name"] = f"MyRenamedCreatedRuleset{idx}"

        # 200 because category is linked to source which is already in DB
        resp = request(reverse("ruleset-detail", args=(rulesets[0].pk,)), params)
        assert resp.status_code == status.HTTP_200_OK


def test_007_update_ruleset_sources_categories(drf: APIClient, source, category):
    params = {
        "name": "MyCreatedRuleset",
        "comment": "My custom ruleset comment",
        "sources": [source.pk],
        "categories": [category.pk],
    }

    # Create valid Ruleset
    resp = drf.post(reverse("ruleset-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED
    rulesets = Ruleset.objects.all()
    assert rulesets.count() == 1

    # PUT/PATCH
    for idx, request in enumerate((drf.put, drf.patch)):
        params["name"] = f"MyRenamedCreatedRuleset{idx}"
        resp = request(reverse("ruleset-detail", args=(rulesets[0].pk,)), params)
        assert resp.status_code == status.HTTP_200_OK


def test_008_copy_ruleset(drf: APIClient, source, source2, category):
    params = {
        "name": "MyCreatedRuleset",
        "comment": "My custom ruleset comment",
        "sources": [source.pk, source2.pk],
        "categories": [category.pk],
    }

    # Create Ruleset
    resp = drf.post(reverse("ruleset-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED
    response = resp.json()
    ruleset = Ruleset.objects.get(pk=response["pk"])

    params = {"name": "MyCreatedRulesetCopy"}
    resp = drf.post(reverse("ruleset-copy", args=(response["pk"],)), params)
    assert resp.status_code == status.HTTP_200_OK

    ruleset_copy = Ruleset.objects.filter(name="MyCreatedRulesetCopy")[0]
    assert ruleset.pk != ruleset_copy.pk
    assert ruleset.sources.count() == ruleset_copy.sources.count()
    assert ruleset.categories.count() == ruleset_copy.categories.count()


def test_009_ruleset_name_unicode(drf: APIClient, source, source2, category):
    name = "Rulesetàççé'-(è&_èç&àç\"ééè-"  # ignore_utf8_check: 224 231 233 232
    params = {
        "name": name,
        "comment": "My custom ruleset comment",
        "sources": [source.pk, source2.pk],
        "categories": [category.pk],
    }

    # Create Ruleset
    resp = drf.post(reverse("ruleset-list"), params)
    assert resp.status_code == status.HTTP_201_CREATED
    assert resp.json()["name"] == name
