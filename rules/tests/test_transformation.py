from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from rules.models.model import (
    Category,
    Rule,
    Ruleset,
    RulesetTransformation,
    Source,
)
from .test_misc import RestAPITestBase


class RestAPIRulesetTransformationTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.source = Source.objects.create(
            name="test source", created_date=timezone.now(), method="local", datatype="sig"
        )
        self.source.save()

        self.category = Category.objects.create(name="test category", filename="test", source=self.source)
        self.category.save()

        self.rule = Rule.objects.create(sid=1, category=self.category, msg="test rule")
        self.rule.save()

        self.ruleset = Ruleset.objects.create(
            name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
        )
        self.ruleset.save()
        self.ruleset.sources.add(self.source)
        self.ruleset.categories.add(self.category)

    def test_001_ruleset_transformations(self):
        params = {"ruleset": self.ruleset.pk, "transfo_type": "action", "transfo_value": "reject"}
        self.http_post(reverse("rulesettransformation-list"), params, status=status.HTTP_201_CREATED)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "lateral", "transfo_value": "yes"}
        self.http_post(reverse("rulesettransformation-list"), params, status=status.HTTP_201_CREATED)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "target", "transfo_value": "src"}
        self.http_post(reverse("rulesettransformation-list"), params, status=status.HTTP_201_CREATED)

        # Create Ruleset Transformation
        action_trans = RulesetTransformation.objects.filter(key="action")
        self.assertEqual(action_trans.count() == 1, True)
        self.assertEqual(action_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(action_trans[0].key == "action", True)
        self.assertEqual(action_trans[0].value == "reject", True)

        lateral_trans = RulesetTransformation.objects.filter(key="lateral")
        self.assertEqual(lateral_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(lateral_trans[0].key == "lateral", True)
        self.assertEqual(lateral_trans[0].value == "yes", True)

        target_trans = RulesetTransformation.objects.filter(key="target")
        self.assertEqual(target_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(target_trans[0].key == "target", True)
        self.assertEqual(target_trans[0].value == "src", True)

        # PATCH Ruleset Transformation
        params = {"ruleset": self.ruleset.pk, "transfo_type": "action", "transfo_value": "drop"}
        self.http_patch(reverse("rulesettransformation-detail", args=(action_trans[0].pk,)), params)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "lateral", "transfo_value": "auto"}
        self.http_patch(reverse("rulesettransformation-detail", args=(lateral_trans[0].pk,)), params)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "target", "transfo_value": "dst"}
        self.http_patch(reverse("rulesettransformation-detail", args=(target_trans[0].pk,)), params)

        action_trans = RulesetTransformation.objects.filter(key="action")
        self.assertEqual(action_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(action_trans[0].key == "action", True)
        self.assertEqual(action_trans[0].value == "drop", True)

        lateral_trans = RulesetTransformation.objects.filter(key="lateral")
        self.assertEqual(lateral_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(lateral_trans[0].key == "lateral", True)
        self.assertEqual(lateral_trans[0].value == "auto", True)

        target_trans = RulesetTransformation.objects.filter(key="target")
        self.assertEqual(target_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(target_trans[0].key == "target", True)
        self.assertEqual(target_trans[0].value == "dst", True)

        # PUT Ruleset Transformation
        params = {"ruleset": self.ruleset.pk, "transfo_type": "action", "transfo_value": "filestore"}
        self.http_put(reverse("rulesettransformation-detail", args=(action_trans[0].pk,)), params)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "lateral", "transfo_value": "yes"}
        self.http_put(reverse("rulesettransformation-detail", args=(lateral_trans[0].pk,)), params)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "target", "transfo_value": "auto"}
        self.http_put(reverse("rulesettransformation-detail", args=(target_trans[0].pk,)), params)

        action_trans = RulesetTransformation.objects.filter(key="action")
        self.assertEqual(action_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(action_trans[0].key == "action", True)
        self.assertEqual(action_trans[0].value == "filestore", True)

        lateral_trans = RulesetTransformation.objects.filter(key="lateral")
        self.assertEqual(lateral_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(lateral_trans[0].key == "lateral", True)
        self.assertEqual(lateral_trans[0].value == "yes", True)

        target_trans = RulesetTransformation.objects.filter(key="target")
        self.assertEqual(target_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(target_trans[0].key == "target", True)
        self.assertEqual(target_trans[0].value == "auto", True)

        # Delete
        self.http_delete(
            reverse("rulesettransformation-detail", args=(action_trans[0].pk,)), status=status.HTTP_204_NO_CONTENT
        )
        self.http_delete(
            reverse("rulesettransformation-detail", args=(lateral_trans[0].pk,)), status=status.HTTP_204_NO_CONTENT
        )
        self.http_delete(
            reverse("rulesettransformation-detail", args=(target_trans[0].pk,)), status=status.HTTP_204_NO_CONTENT
        )
        rulesets = RulesetTransformation.objects.all()
        self.assertEqual(rulesets.count(), 0)
