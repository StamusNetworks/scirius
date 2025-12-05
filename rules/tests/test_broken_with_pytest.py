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
)

from .test_misc import RestAPITestBase


RULE_CONTENT = 'alert ip any any -> any any (msg:"Unicode test rule éàç"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)\n'  # ignore_utf8_check: 233 224 231


class RestAPISourceTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.ruleset = Ruleset.objects.create(
            name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
        )
        self.ruleset.save()

    def _create_public_source(self):
        params = {
            "name": "sonic test public source",
            "comment": "MyPublicComment",
            "public_source": "oisf/trafficid",
        }
        self.http_post(reverse("publicsource-list"), params, status=status.HTTP_201_CREATED)
        sources = Source.objects.filter(name="sonic test public source")
        self.assertEqual(sources.count() == 1, True)

        self.public_source = sources.first()
        self.ruleset.sources.add(sources.first())

    def _create_custom_source(self, method, datatype, **kwargs):
        params = {
            "name": "sonic test custom source",
            "comment": "MyCustomComment",
            "method": method,
            "datatype": datatype,
        }
        params.update(kwargs)
        self.http_post(reverse("source-list"), params, status=status.HTTP_201_CREATED)
        sources = Source.objects.filter(name="sonic test custom source")
        self.assertEqual(sources.count() == 1, True)

        self.source = sources.first()
        self.ruleset.sources.add(sources.first())

    def _set_source_from_name(self, name):
        sources = Source.objects.filter(name=name)
        self.assertEqual(sources.count(), 1)
        self.source = sources[0]

    # def test_000_custom_source_iprep(self):
    #     self._create_custom_source('http', 'sigs', uri=ET_URL, cert_verif=True, use_iprep=False)
    #     response = self.http_get(reverse('source-list'))
    #     self.assertIn('results', response)

    #     results = response.get('results', [])
    #     self.assertIn('use_iprep', results[0])
    #     self.assertEqual(results[0]['use_iprep'], False)

    #     self.source.update()
    #     category = self.source.category_set.get(name='botcc')
    #     rules = category.rule_set.filter(msg__contains='ET CNC Feodo Tracker Reported CnC Server group')

    #     size = rules.count()
    #     self.assertGreater(size, 1)
    #     for rule in rules:
    #         self.assertIn('group', rule.msg)

    #     response = self.http_patch(reverse('source-detail', args=(self.source.pk,)), {'use_iprep': True, 'version': 1})
    #     self.assertEqual(response['use_iprep'], True)

    #     self._set_source_from_name('sonic test custom source')
    #     self.source.update()
    #     category = self.source.category_set.get(name='botcc')
    #     rules = category.rule_set.filter(msg__contains='ET CNC Feodo Tracker Reported CnC Server')
    #     self.assertEqual(rules.count(), 1)
    #     self.assertIn('iprep', rules[0].ruleatversion_set.first().content)

    #     response = self.http_patch(reverse('source-detail', args=(self.source.pk,)), {'use_iprep': False, 'version': 1})
    #     self.assertEqual(response['use_iprep'], False)

    #     self._set_source_from_name('sonic test custom source')
    #     self.source.update()
    #     category = self.source.category_set.get(name='botcc')
    #     rules = category.rule_set.filter(msg__contains='ET CNC Feodo Tracker Reported CnC Server')
    #     self.assertEqual(size, rules.count())

    # maybe require suricata and a specific configuration when check_rule_buffer() is called
    def test_001_public_source(self):
        self._create_public_source()
        response = self.http_get(reverse("publicsource-fetch-list-sources"))
        self.assertDictEqual(response, {"fetch": "ok"})

        self.public_source.update()

        # behavior/status could be different on remote and local build
        test_results = self.public_source.test()

        if test_results["status"] is True:
            self.http_get(reverse("publicsource-list-sources"))
        else:
            self.assertTrue("errors" in test_results)

        response = self.http_delete(
            reverse("publicsource-detail", args=(self.public_source.pk,)), status=status.HTTP_204_NO_CONTENT
        )
        sources = Source.objects.filter(pk=self.public_source.pk)
        self.assertEqual(sources.count(), 0)

    def test_002_custom_source_upload(self):
        from io import BytesIO

        self._create_custom_source("local", "sig")
        self.source.new_uploaded_file(BytesIO(RULE_CONTENT.encode("utf-8")))

        self.http_post(reverse("source-update-source", args=(self.source.pk,)), status=status.HTTP_400_BAD_REQUEST)

        response = self.http_get(reverse("category-list") + "?source=%i" % self.source.pk)
        categories = response.get("results", [])
        self.assertEqual(len(categories), 1)

        response = self.http_get(reverse("rule-list") + "?category=%i" % categories[0]["pk"])
        rules = response.get("results", [])
        self.assertEqual(len(rules), 1)

        rule = rules[0]

        self.assertDictContainsSubset(
            {
                "sid": 2100498,
                "msg": "Unicode test rule éàç",  # ignore_utf8_check: 233 224 231
            },
            rule,
        )

        self.assertDictContainsSubset(
            {"state": True, "commented_in_source": False, "content": RULE_CONTENT, "rev": 7}, rule["versions"][0]
        )


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
