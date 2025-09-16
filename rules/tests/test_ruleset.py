from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from rules.models.model import (
    Category,
    Rule,
    Ruleset,
    Source,
)
from .test_misc import RestAPITestBase


class RestAPIRulesetTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.source = Source.objects.create(
            name="test source", created_date=timezone.now(), method="local", datatype="sig"
        )
        self.source.save()

        self.source2 = Source.objects.create(
            name="test source 2", created_date=timezone.now(), method="local", datatype="sig"
        )
        self.source2.save()

        self.category = Category.objects.create(name="test category", filename="test", source=self.source)
        self.category.save()

        self.rule = Rule.objects.create(sid=1, category=self.category, msg="test rule")
        self.rule.save()

    def test_001_ruleset_actions(self):
        params = {
            "name": "MyCreatedRuleset",
            "comment": "My custom ruleset comment",
            "sources": [self.source.pk, self.source2.pk],
            "categories": [self.category.pk],
        }

        # Create Ruleset
        self.http_post(reverse("ruleset-list"), params, status=status.HTTP_201_CREATED)
        rulesets = Ruleset.objects.all()
        sources = rulesets[0].sources.all()

        self.assertEqual(rulesets.count(), 1)
        self.assertEqual(rulesets[0].name, "MyCreatedRuleset")
        self.assertEqual(rulesets[0].categories.count() > 0, True)
        self.assertEqual(sources.count() == 2, True)

        for src in sources:
            self.assertEqual(src in [self.source, self.source2], True)

        # PUT/PATCH Ruleset
        for idx, request in enumerate((self.http_put, self.http_patch)):
            params["name"] = f"MyRenamedCreatedRuleset{idx}"

            status_ = status.HTTP_200_OK
            if request == self.http_patch:
                params["sources"] = []
                status_ = status.HTTP_400_BAD_REQUEST

            request(reverse("ruleset-detail", args=(rulesets[0].pk,)), params, status=status_)

            status_ = status.HTTP_200_OK
            if request == self.http_patch:
                del params["sources"]
                status_ = status.HTTP_400_BAD_REQUEST

            request(reverse("ruleset-detail", args=(rulesets[0].pk,)), params, status=status.HTTP_200_OK)

            rulesets = Ruleset.objects.all()
            self.assertEqual(rulesets.count(), 1)
            self.assertEqual(rulesets[0].name, "MyRenamedCreatedRuleset%s" % idx)

            self.assertEqual(rulesets[0].sources.count() == 2, True)

        # Delete
        rulesets = Ruleset.objects.all()
        self.assertEqual(rulesets.count(), 1)
        self.http_delete(reverse("ruleset-detail", args=(rulesets[0].pk,)), status=status.HTTP_204_NO_CONTENT)
        rulesets = Ruleset.objects.all()
        self.assertEqual(rulesets.count(), 0)

    def test_002_create_ruleset_source_wrong_category(self):
        params = {
            "name": "MyCreatedRuleset",
            "comment": "My custom ruleset comment",
            "sources": [self.source2.pk],
            "categories": [self.category.pk],
        }

        self.http_post(reverse("ruleset-list"), params, status=status.HTTP_400_BAD_REQUEST)

    def test_003_create_ruleset_no_source_categories(self):
        params = {"name": "MyCreatedRuleset", "comment": "My custom ruleset comment", "categories": [self.category.pk]}

        self.http_post(reverse("ruleset-list"), params, status=status.HTTP_400_BAD_REQUEST)

    def test_004_create_ruleset_sources_categories(self):
        params = {
            "name": "MyCreatedRuleset",
            "comment": "My custom ruleset comment",
            "sources": [self.source.pk],
            "categories": [self.category.pk],
        }

        self.http_post(reverse("ruleset-list"), params, status=status.HTTP_201_CREATED)

    def test_005_update_ruleset_source_wrong_category(self):
        params = {
            "name": "MyCreatedRuleset",
            "comment": "My custom ruleset comment",
            "sources": [self.source.pk],
            "categories": [self.category.pk],
        }

        # Create valid Ruleset
        self.http_post(reverse("ruleset-list"), params, status=status.HTTP_201_CREATED)
        rulesets = Ruleset.objects.all()
        self.assertEqual(rulesets.count(), 1)

        # PUT/PATCH
        params["sources"] = [self.source2.pk]
        for idx, request in enumerate((self.http_put, self.http_patch)):
            params["name"] = f"MyRenamedCreatedRuleset{idx}"
            request(reverse("ruleset-detail", args=(rulesets[0].pk,)), params, status=status.HTTP_400_BAD_REQUEST)

    def test_006_update_ruleset_no_source_categories(self):
        params = {
            "name": "MyCreatedRuleset",
            "comment": "My custom ruleset comment",
            "sources": [self.source.pk],
            "categories": [self.category.pk],
        }

        # Create valid Ruleset
        self.http_post(reverse("ruleset-list"), params, status=status.HTTP_201_CREATED)
        rulesets = Ruleset.objects.all()
        self.assertEqual(rulesets.count(), 1)

        # PUT/PATCH
        params.pop("sources")
        for idx, request in enumerate((self.http_put, self.http_patch)):
            params["name"] = f"MyRenamedCreatedRuleset{idx}"

            # 200 because category is linked to source which is already in DB
            request(reverse("ruleset-detail", args=(rulesets[0].pk,)), params, status=status.HTTP_200_OK)

    def test_007_update_ruleset_sources_categories(self):
        params = {
            "name": "MyCreatedRuleset",
            "comment": "My custom ruleset comment",
            "sources": [self.source.pk],
            "categories": [self.category.pk],
        }

        # Create valid Ruleset
        self.http_post(reverse("ruleset-list"), params, status=status.HTTP_201_CREATED)
        rulesets = Ruleset.objects.all()
        self.assertEqual(rulesets.count(), 1)

        # PUT/PATCH
        for idx, request in enumerate((self.http_put, self.http_patch)):
            params["name"] = f"MyRenamedCreatedRuleset{idx}"
            request(reverse("ruleset-detail", args=(rulesets[0].pk,)), params, status=status.HTTP_200_OK)

    def test_008_copy_ruleset(self):
        params = {
            "name": "MyCreatedRuleset",
            "comment": "My custom ruleset comment",
            "sources": [self.source.pk, self.source2.pk],
            "categories": [self.category.pk],
        }

        # Create Ruleset
        response = self.http_post(reverse("ruleset-list"), params, status=status.HTTP_201_CREATED)
        ruleset = Ruleset.objects.get(pk=response["pk"])

        params = {"name": "MyCreatedRulesetCopy"}
        self.http_post(reverse("ruleset-copy", args=(response["pk"],)), params, status=status.HTTP_200_OK)

        ruleset_copy = Ruleset.objects.filter(name="MyCreatedRulesetCopy")[0]
        self.assertNotEqual(ruleset.pk, ruleset_copy.pk)
        self.assertEqual(ruleset.sources.count(), ruleset_copy.sources.count())
        self.assertEqual(ruleset.categories.count(), ruleset_copy.categories.count())

    def test_009_ruleset_name_unicode(self):
        name = "Rulesetàççé'-(è&_èç&àç\"ééè-"  # ignore_utf8_check: 224 231 233 232
        params = {
            "name": name,
            "comment": "My custom ruleset comment",
            "sources": [self.source.pk, self.source2.pk],
            "categories": [self.category.pk],
        }

        # Create Ruleset
        response = self.http_post(reverse("ruleset-list"), params, status=status.HTTP_201_CREATED)
        self.assertEqual(response["name"], name)
