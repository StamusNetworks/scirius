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
    RuleProcessingFilter,
)
from .test_misc import RestAPITestBase

from copy import deepcopy
from importlib import import_module


class RestAPIRuleProcessingFilterTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)
        self.list_url = reverse("ruleprocessingfilter-list")
        self.detail_url = lambda x: reverse("ruleprocessingfilter-detail", args=(x,))

        import scirius.utils

        self.middleware = scirius.utils.get_middleware_module

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

        self.rule = Rule.objects.create(sid=1, category=self.category, msg="test rule")
        self.rule.save()
        RuleAtVersion.objects.create(rule=self.rule, content=content)

        self.rule2 = Rule.objects.create(sid=2, category=self.category, msg="whatever DNS Query for whatever")
        self.rule2.save()
        RuleAtVersion.objects.create(rule=self.rule2, content=content)

        self.rule3 = Rule.objects.create(
            sid=3, category=self.category, msg="other content DNS Query for another content"
        )
        self.rule3.save()
        RuleAtVersion.objects.create(rule=self.rule3, content=content2)

        self.rule4 = Rule.objects.create(
            sid=4, category=self.category, msg="other content DNS Query for another content"
        )
        self.rule4.save()
        RuleAtVersion.objects.create(rule=self.rule4, content=content3)

        self.ruleset = Ruleset.objects.create(
            name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
        )
        self.ruleset.save()
        self.ruleset.sources.add(self.source)
        self.ruleset.categories.add(self.category)

        self.DEFAULT_FILTER = {
            "filter_defs": [{"key": "event_type", "value": "http", "operator": "equal", "full_string": True}],
            "action": "suppress",
            "index": 0,
            "rulesets": [self.ruleset.pk],
        }
        self.DEFAULT_FILTER2 = {
            "filter_defs": [{"key": "host", "value": "probe-test", "operator": "equal", "full_string": True}],
            "action": "suppress",
            "index": 0,
            "rulesets": [self.ruleset.pk],
        }

    def tearDown(self):
        import scirius.utils

        scirius.utils.get_middleware_module = self.middleware

    def _force_suricata_middleware(self):
        import scirius.utils

        scirius.utils.get_middleware_module = lambda x: import_module("suricata.%s" % x)

    def test_013_suppress_validation_error(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f["options"] = {"test": "test"}
        r = self.http_post(self.list_url, f, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {"options": ['Action "suppress" does not accept options.']})

    def test_015_threshold_create_invalid(self):
        r = self.http_post(
            self.list_url,
            {
                "filter_defs": [{"key": "alert.sid", "value": "1", "operator": "equal", "full_string": True}],
                "action": "threshold",
                "options": {"count": 2, "seconds": 30, "track": "by_src"},
                "rulesets": [self.ruleset.pk],
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
        self.assertDictEqual(r, {"options": [{"type": ["This field is required."]}]})

    def test_019_suri_filter_defs_invalid(self):
        self._force_suricata_middleware()
        r = self.http_post(
            self.list_url,
            {
                "filter_defs": [{"key": "src_ip", "value": "192.168.0.1", "operator": "equal", "full_string": True}],
                "action": "suppress",
                "rulesets": [self.ruleset.pk],
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
        self.assertDictEqual(
            r,
            {
                "filter_defs": [
                    'A filter with a key "alert.signature_id" or "msg" or "alert.signature" or "content" is required.'
                ]
            },
        )

    def test_020_suri_suppress_generate(self):
        self.http_post(
            self.list_url,
            {
                "filter_defs": [
                    {"key": "src_ip", "value": "192.168.0.1", "operator": "equal"},
                    {"key": "alert.signature_id", "value": "1", "operator": "equal"},
                ],
                "action": "suppress",
                "rulesets": [self.ruleset.pk],
            },
            status=status.HTTP_201_CREATED,
        )

        f = RuleProcessingFilter.objects.all()[0]
        suppress = f.get_threshold_content()
        self.assertEqual(suppress, ["suppress gen_id 1, sid_id 1, track by_src, ip 192.168.0.1\n"])

    def test_021_suri_threshold_generate(self):
        r = self.http_post(
            self.list_url,
            {
                "filter_defs": [
                    {"key": "dest_ip", "value": "192.168.0.1", "operator": "equal", "full_string": True},
                    {"key": "alert.signature_id", "value": "1", "operator": "equal", "full_string": True},
                ],
                "action": "threshold",
                "options": {"type": "both", "track": "by_dst"},
                "rulesets": [self.ruleset.pk],
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

        self.assertDictEqual(r, {"filter_defs": ['Field "dest_ip" is not supported for threshold.']})

    def test_022_ip_validation(self):
        r = self.http_post(
            self.list_url,
            {
                "filter_defs": [{"key": "dest_ip", "value": "192.168.0.", "operator": "equal"}],
                "action": "suppress",
                "rulesets": [self.ruleset.pk],
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
        self.assertDictEqual(r, {"filter_defs": [{"value": ["This field requires a valid IP address."]}]})

    def test_023_capabilities_test(self):
        self._force_suricata_middleware()
        r = self.http_post(
            reverse("ruleprocessingfilter-test"), {"fields": ["src_ip", "dns.rdata"], "action": "suppress"}
        )
        supported_fields = sorted(r.pop("supported_fields").split(", "))
        self.assertDictEqual(r, {"fields": ["src_ip"], "operators": ["equal"]})
        self.assertEqual(
            supported_fields,
            [
                "alert.signature",
                "alert.signature_id",
                "alert.source.ip",
                "alert.target.ip",
                "content",
                "dest_ip",
                "msg",
                "src_ip",
            ],
        )

    def test_024_capabilities_test(self):
        self._force_suricata_middleware()
        r = self.http_post(
            reverse("ruleprocessingfilter-test"), {"fields": ["src_ip", "dns.rdata"], "action": "threshold"}
        )
        supported_fields = sorted(r.pop("supported_fields").split(", "))
        self.assertDictEqual(r, {"fields": [], "operators": ["equal"]})
        self.assertEqual(supported_fields, ["alert.signature", "alert.signature_id", "content", "msg"])

    def test_124_srcip_msg_validation(self):
        self._force_suricata_middleware()
        self.http_post(
            self.list_url,
            {
                "filter_defs": [
                    {"key": "src_ip", "value": "192.168.0.1", "operator": "equal"},
                    {"key": "msg", "value": "DNS Query for", "operator": "equal"},
                ],
                "action": "suppress",
                "rulesets": [self.ruleset.pk],
            },
            status=status.HTTP_201_CREATED,
        )

        f = RuleProcessingFilter.objects.all()[0]
        suppress = f.get_threshold_content(self.ruleset)
        self.assertEqual(
            suppress,
            [
                "suppress gen_id 1, sid_id 2, track by_src, ip 192.168.0.1\n",
                "suppress gen_id 1, sid_id 3, track by_src, ip 192.168.0.1\n",
                "suppress gen_id 1, sid_id 4, track by_src, ip 192.168.0.1\n",
            ],
        )

    def test_125_target_src_msg_validation(self):
        self._force_suricata_middleware()
        self.http_post(
            self.list_url,
            {
                "filter_defs": [
                    {"key": "alert.target.ip", "value": "192.168.0.1", "operator": "equal"},
                    {"key": "msg", "value": "another content", "operator": "equal"},
                ],
                "action": "suppress",
                "rulesets": [self.ruleset.pk],
            },
            status=status.HTTP_201_CREATED,
        )

        f = RuleProcessingFilter.objects.all()[0]
        suppress = f.get_threshold_content(self.ruleset)
        self.assertEqual(
            suppress,
            [
                "suppress gen_id 1, sid_id 3, track by_dst, ip 192.168.0.1\n",
                "suppress gen_id 1, sid_id 4, track by_src, ip 192.168.0.1\n",
            ],
        )
