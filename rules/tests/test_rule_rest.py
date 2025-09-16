from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

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
from .test_misc import RestAPITestBase


class RestAPIRuleTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.source = Source.objects.create(
            name="test source", created_date=timezone.now(), method="local", datatype="sig"
        )
        self.source.save()
        self.category = Category.objects.create(name="test category", filename="test", source=self.source)
        self.category.save()

        content = (
            'alert ip $HOME_NET any -> [103.207.29.161,103.207.29.171,103.225.168.222,103.234.36.190,103.234.37.4,103.4.164.34, \
103.6.207.37,104.131.93.109,104.140.137.152,104.143.5.144,104.144.167.131,104.144.167.251,104.194.206.108, \
104.199.121.36,104.207.154.26,104.223.87.207,104.43.200.222,106.187.48.236,107.161.19.71] \
any (msg:"ET CNC Shadowserver Reported CnC Server IP group 1"; \
reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,www.shadowserver.org;\
threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; \
flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404000; rev:4933;)'
        )

        self.rule = Rule.objects.create(sid=1, category=self.category, msg="test rule")
        self.rule.save()
        RuleAtVersion.objects.create(rule=self.rule, content=content)
        self.ruleset = Ruleset.objects.create(
            name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
        )
        self.ruleset.save()
        self.ruleset.sources.add(self.source)
        self.ruleset.categories.add(self.category)

    def test_001_rule_detail(self):
        self.http_get(reverse("rule-detail", args=(self.rule.pk,)))

    def test_002_rule_disable(self):
        nb_items = SuppressedRuleAtVersion.objects.filter(
            ruleset=self.ruleset, rule_at_version=self.rule.ruleatversion_set.first()
        ).count()
        self.assertEqual(nb_items, 0)

        self.http_post(reverse("rule-disable", args=(self.rule.pk,)), {"ruleset": self.ruleset.pk})
        self.ruleset.refresh_from_db()

        nb_items = SuppressedRuleAtVersion.objects.filter(
            ruleset=self.ruleset, rule_at_version=self.rule.ruleatversion_set.first()
        ).count()
        item = SuppressedRuleAtVersion.objects.filter(
            ruleset=self.ruleset, rule_at_version=self.rule.ruleatversion_set.first()
        ).first()
        self.assertEqual(nb_items, 1)
        self.assertEqual(item.rule_at_version.pk, self.rule.ruleatversion_set.first().pk)
        self.assertEqual(item.rule_at_version.rule.pk, self.rule.pk)

        self.http_post(reverse("rule-enable", args=(self.rule.pk,)), {"ruleset": self.ruleset.pk})
        self.ruleset.refresh_from_db()

        nb_items = SuppressedRuleAtVersion.objects.filter(
            ruleset=self.ruleset, rule_at_version=self.rule.ruleatversion_set.first()
        ).count()
        self.assertEqual(nb_items, 0)

    def test_003_rule_permission(self):
        self.client.logout()

        # Non logged request are rejected
        self.http_post(
            reverse("rule-disable", args=(self.rule.pk,)),
            {"ruleset": self.ruleset.pk},
            status=status.HTTP_403_FORBIDDEN,
        )

        self.client.force_login(self.user)
        # Read still authorized
        self.http_post(
            reverse("rule-disable", args=(self.rule.pk,)), {"ruleset": self.ruleset.pk}, status=status.HTTP_200_OK
        )

        # Post not authorized non-role
        self.superuser_role.user_set.remove(self.user)
        self.http_post(
            reverse("rule-disable", args=(self.rule.pk,)),
            {"ruleset": self.ruleset.pk},
            status=status.HTTP_403_FORBIDDEN,
        )

        # Post authorized staff role
        self.staff_role.user_set.add(self.user)
        self.http_post(
            reverse("rule-disable", args=(self.rule.pk,)), {"ruleset": self.ruleset.pk}, status=status.HTTP_200_OK
        )

        # Post not authorized user role
        self.staff_role.user_set.remove(self.user)
        self.user_role.user_set.add(self.user)
        self.http_post(
            reverse("rule-disable", args=(self.rule.pk,)),
            {"ruleset": self.ruleset.pk},
            status=status.HTTP_403_FORBIDDEN,
        )

    def test_004_rule_transformation(self):
        # Transform ruleset
        self.http_post(
            reverse("rulesettransformation-list"),
            {
                "ruleset": self.ruleset.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_FILESTORE.value,
            },
            status=status.HTTP_201_CREATED,
        )

        # Check inheritance on category
        transformation = self.category.get_transformation(
            ruleset=self.ruleset, key=Transformation.ACTION, override=True
        )
        self.assertEqual(transformation, Transformation.A_FILESTORE)

        # Check inheritance on rule
        transformation = self.rule.get_transformation(ruleset=self.ruleset, key=Transformation.ACTION, override=True)
        self.assertEqual(transformation, Transformation.A_FILESTORE)

        # Transform Category
        self.http_post(
            reverse("categorytransformation-list"),
            {
                "category": self.category.pk,
                "ruleset": self.ruleset.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_DROP.value,
            },
            status=status.HTTP_201_CREATED,
        )

        # Check category transformation
        transformation = self.category.get_transformation(ruleset=self.ruleset, key=Transformation.ACTION)
        self.assertEqual(transformation, Transformation.A_DROP)

        # Check inheritance on rule (from category)
        transformation = self.rule.get_transformation(ruleset=self.ruleset, key=Transformation.ACTION, override=True)
        self.assertEqual(transformation, Transformation.A_DROP)

        # Transform rule
        self.http_post(
            reverse("ruletransformation-list"),
            {
                "rule": self.rule.pk,
                "ruleset": self.ruleset.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_REJECT.value,
            },
            status=status.HTTP_201_CREATED,
        )

        # Check transformed rule
        transformed = self.ruleset.get_transformed_rules(key=Transformation.ACTION, value=Transformation.A_REJECT)
        self.assertEqual(transformed.count(), 1)
        self.assertEqual(transformed[0].pk, self.rule.pk)

        transformation = self.rule.get_transformation(ruleset=self.ruleset, key=Transformation.ACTION)
        self.assertEqual(transformation, Transformation.A_REJECT)

        # Transform same rule
        self.ruletransformation = RuleTransformation.objects.filter(rule_transformation=self.rule, ruleset=self.ruleset)
        self.http_patch(
            reverse("ruletransformation-detail", args=(self.ruletransformation[0].pk,)),
            {
                "rule": self.rule.pk,
                "ruleset": self.ruleset.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_DROP.value,
            },
        )

        transformed = self.ruleset.get_transformed_rules(key=Transformation.ACTION, value=Transformation.A_REJECT)
        self.assertEqual(transformed.count(), 0)

    def test_005_rule_transformation_content(self):
        version = 0
        self.http_post(
            reverse("rulesettransformation-list"),
            {
                "ruleset": self.ruleset.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_DROP.value,
            },
            status=status.HTTP_201_CREATED,
        )

        content = self.http_get(reverse("rule-content", args=(self.rule.pk,)))
        self.assertEqual("drop" in content[self.ruleset.pk][version], True)

        self.http_post(
            reverse("categorytransformation-list"),
            {
                "category": self.category.pk,
                "ruleset": self.ruleset.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_REJECT.value,
            },
            status=status.HTTP_201_CREATED,
        )

        content = self.http_get(reverse("rule-content", args=(self.rule.pk,)))
        self.assertEqual("reject" in content[self.ruleset.pk][version], True)

        self.http_post(
            reverse("ruletransformation-list"),
            {
                "rule": self.rule.pk,
                "ruleset": self.ruleset.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_DROP.value,
            },
            status=status.HTTP_201_CREATED,
        )

        content = self.http_get(reverse("rule-content", args=(self.rule.pk,)))
        self.assertEqual("drop" in content[self.ruleset.pk][version], True)

    def test_006_rule_status(self):
        self.http_post(
            reverse("rulesettransformation-list"),
            {
                "ruleset": self.ruleset.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_DROP.value,
            },
            status=status.HTTP_201_CREATED,
        )

        status_ = self.http_get(reverse("rule-status", args=(self.rule.pk,)))
        self.assertTrue(self.ruleset.pk in status_)
        self.assertEqual(status_[self.ruleset.pk]["transformations"]["action"], "drop")

        self.http_post(
            reverse("categorytransformation-list"),
            {
                "category": self.category.pk,
                "ruleset": self.ruleset.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_REJECT.value,
            },
            status=status.HTTP_201_CREATED,
        )

        status_ = self.http_get(reverse("rule-status", args=(self.rule.pk,)))
        self.assertTrue(self.ruleset.pk in status_)
        self.assertEqual(status_[self.ruleset.pk]["transformations"]["action"], "reject")

    def test_007_rule_toggle_availability(self):
        self.http_post(reverse("rule-toggle-availability", args=(self.rule.pk,)), {}, status=status.HTTP_200_OK)
        rule = Rule.objects.get(pk=self.rule.pk)
        for rav in rule.ruleatversion_set.all():
            self.assertEqual(rav.state, False)

        self.http_post(reverse("rule-toggle-availability", args=(self.rule.pk,)), {}, status=status.HTTP_200_OK)
        rule = Rule.objects.get(pk=self.rule.pk)
        for rav in rule.ruleatversion_set.all():
            self.assertEqual(rav.state, True)

    def test_008_rule_comment(self):
        comment = "Need a comment for my test."
        self.http_post(reverse("rule-comment", args=(self.rule.pk,)), {"comment": comment})

        ua = UserAction.objects.order_by("pk").last()
        self.assertEqual(ua.comment, comment)

    def test_009_get_transformed_rules(self):
        # Transform ruleset
        self.http_post(
            reverse("rulesettransformation-list"),
            {
                "ruleset": self.ruleset.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_REJECT.value,
            },
            status=status.HTTP_201_CREATED,
        )
        params = f"?transfo_type={Transformation.ACTION.value}&transfo_value={Transformation.A_REJECT.value}"
        content = self.http_get(reverse("rule-transformation") + params)

        self.assertEqual(self.ruleset.pk in content, True)
        self.assertEqual(content[self.ruleset.pk]["rules"][0], self.rule.pk)
        self.assertEqual(content[self.ruleset.pk]["transformation"]["transfo_key"], Transformation.ACTION.value)
        self.assertEqual(content[self.ruleset.pk]["transformation"]["transfo_value"], Transformation.A_REJECT.value)

        self.http_post(
            reverse("categorytransformation-list"),
            {
                "ruleset": self.ruleset.pk,
                "category": self.category.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_DROP.value,
            },
            status=status.HTTP_201_CREATED,
        )
        params = f"?transfo_type={Transformation.ACTION.value}&transfo_value={Transformation.A_DROP.value}"
        content = self.http_get(reverse("rule-transformation") + params)

        self.assertEqual(self.ruleset.pk in content, True)
        self.assertEqual(content[self.ruleset.pk]["rules"][0], self.rule.pk)
        self.assertEqual(content[self.ruleset.pk]["transformation"]["transfo_key"], Transformation.ACTION.value)
        self.assertEqual(content[self.ruleset.pk]["transformation"]["transfo_value"], Transformation.A_DROP.value)

        self.http_post(
            reverse("ruletransformation-list"),
            {
                "ruleset": self.ruleset.pk,
                "rule": self.rule.pk,
                "transfo_type": Transformation.ACTION.value,
                "transfo_value": Transformation.A_BYPASS.value,
            },
            status=status.HTTP_201_CREATED,
        )
        self.assertEqual(self.ruleset.pk in content, True)
        params = f"?transfo_type={Transformation.ACTION.value}&transfo_value={Transformation.A_BYPASS.value}"
        content = self.http_get(reverse("rule-transformation") + params)

        self.assertEqual(self.ruleset.pk in content, True)
        self.assertEqual(content[self.ruleset.pk]["rules"][0], self.rule.pk)
        self.assertEqual(content[self.ruleset.pk]["transformation"]["transfo_key"], Transformation.ACTION.value)
        self.assertEqual(content[self.ruleset.pk]["transformation"]["transfo_value"], Transformation.A_BYPASS.value)
