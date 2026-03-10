from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from rules.models.model import (
    # Category,
    # Rule,
    # RuleAtVersion,
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
