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
    UserAction,
    RuleProcessingFilter,
    RuleProcessingFilterDef,
)
from .test_misc import RestAPITestBase

from copy import deepcopy
import itertools


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

    def _remove_filters_pk(self, f):
        for f_def in f["filter_defs"]:
            f_def.pop("pk", None)

    def test_001_create(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f["comment"] = "test comment"
        r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
        self._remove_filters_pk(r)
        self.assertDictContainsSubset(self.DEFAULT_FILTER, r)
        self.filter_pk = r["pk"]
        ua = UserAction.objects.last()
        self.assertEqual(ua.action_type, "create_rule_filter")
        self.assertEqual(ua.comment, "test comment")

    def test_002_create_invalid_filter(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f["filter_defs"] = []
        r = self.http_post(self.list_url, f, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {"filter_defs": ["This field is required."]})
        self.assertEqual(RuleProcessingFilter.objects.count(), 0)
        self.assertEqual(RuleProcessingFilterDef.objects.count(), 0)

        f = deepcopy(self.DEFAULT_FILTER)
        f["filter_defs"] = [{"key": "test", "operator": "equal"}]
        r = self.http_post(self.list_url, f, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {"filter_defs": [{"value": ["This field is required."]}]})
        self.assertEqual(RuleProcessingFilter.objects.count(), 0)
        self.assertEqual(RuleProcessingFilterDef.objects.count(), 0)

    def test_003_update_filter_existing(self):
        self.test_001_create()

        r = self.http_patch(
            self.detail_url(self.filter_pk),
            {"filter_defs": [{"key": "event_type", "value": "dns", "operator": "equal"}], "comment": "test comment"},
        )

        f = deepcopy(self.DEFAULT_FILTER)
        f["filter_defs"][0]["value"] = "dns"
        self._remove_filters_pk(r)
        self.assertDictContainsSubset(f, r)

        ua = UserAction.objects.last()
        self.assertEqual(ua.action_type, "edit_rule_filter")
        self.assertEqual(ua.comment, "test comment")

    def test_004_update_filter_add(self):
        self.test_001_create()

        # Filter value update
        new_filter = {"key": "host", "value": "probe1", "operator": "equal", "full_string": True}
        filters = deepcopy(self.DEFAULT_FILTER["filter_defs"])
        filters.append(new_filter)

        r = self.http_patch(self.detail_url(self.filter_pk), {"filter_defs": filters})

        f = deepcopy(self.DEFAULT_FILTER)
        f["filter_defs"].append(new_filter)
        self._remove_filters_pk(r)
        self.assertDictContainsSubset(f, r)
        self.assertEqual(len(r["filter_defs"]), 2)

    def test_005_update_filter_rm(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f["filter_defs"].append({"key": "host", "value": "probe1", "operator": "equal", "full_string": True})

        r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
        r["filter_defs"][0].pop("pk")
        r["filter_defs"][1].pop("pk")
        self.assertDictContainsSubset(f, r)

        r = self.http_patch(self.detail_url(r["pk"]), {"filter_defs": self.DEFAULT_FILTER["filter_defs"]})

        self._remove_filters_pk(r)
        self.assertDictContainsSubset(self.DEFAULT_FILTER, r)
        self.assertEqual(len(r["filter_defs"]), 1)

    def test_006_order_create_empty(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f.pop("index")

        r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
        self._remove_filters_pk(r)
        self.assertDictContainsSubset(self.DEFAULT_FILTER, r)

    def test_007_order_create_append(self):
        self.test_001_create()

        f = deepcopy(self.DEFAULT_FILTER2)
        f.pop("index")

        r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
        self._remove_filters_pk(r)
        f = deepcopy(self.DEFAULT_FILTER2)
        f["index"] = 1

        self.assertDictContainsSubset(f, r)

        r = self.http_get(self.list_url)
        self._remove_filters_pk(r["results"][0])
        self.assertDictContainsSubset(self.DEFAULT_FILTER, r["results"][0])
        self._remove_filters_pk(r["results"][1])
        self.assertDictContainsSubset(f, r["results"][1])

    def test_008_order_create_insert(self):
        self.test_001_create()

        self.http_post(self.list_url, self.DEFAULT_FILTER2, status=status.HTTP_201_CREATED)

        f1 = deepcopy(self.DEFAULT_FILTER)
        f1["index"] = 1

        r = self.http_get(self.list_url)
        self._remove_filters_pk(r["results"][0])
        self.assertDictContainsSubset(self.DEFAULT_FILTER2, r["results"][0])
        self._remove_filters_pk(r["results"][1])
        self.assertDictContainsSubset(f1, r["results"][1])

    def test_009_order_create_oob(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f["index"] = 1
        r = self.http_post(self.list_url, f, status=status.HTTP_400_BAD_REQUEST)

        self.assertDictEqual(r, {"index": ["Invalid index value (too high)."]})

    def _check_order(self, expected):
        r = self.http_get(self.list_url)
        order = [f["pk"] for f in r["results"]]
        self.assertListEqual(expected, order)
        indices = [f["index"] for f in r["results"]]
        self.assertListEqual(indices, list(range(4)))

    def _test_010_order_update(self, prev_index, new_index):
        filters = []
        for i in range(4):
            f = deepcopy(self.DEFAULT_FILTER)
            f.pop("index")
            r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
            filters.append(r["pk"])

        pk_to_move = filters[prev_index]
        expected = deepcopy(filters)

        if new_index is None:
            expected.pop(prev_index)
            expected.append(pk_to_move)
        else:
            if prev_index != new_index:
                expected.pop(prev_index)

                if new_index < len(filters):
                    insert_before_pk = filters[new_index]
                    _new_index = expected.index(insert_before_pk)
                    expected.insert(_new_index, pk_to_move)
                else:
                    expected.append(pk_to_move)

        self.http_patch(self.detail_url(pk_to_move), {"index": new_index})
        self._check_order(expected)

    def test_011_order_update_oob(self):
        self.test_001_create()
        r = self.http_patch(self.detail_url(self.filter_pk), {"index": 2}, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {"index": ["Invalid index value (too high)."]})

    def test_012_delete(self):
        self.test_007_order_create_append()

        self.http_delete(
            self.detail_url(self.filter_pk), {"comment": "test comment"}, status=status.HTTP_204_NO_CONTENT
        )
        r = self.http_get(self.list_url)

        self.assertEqual(r["count"], 1)
        self._remove_filters_pk(r["results"][0])
        self.assertDictContainsSubset(self.DEFAULT_FILTER2, r["results"][0])

        ua = UserAction.objects.last()
        self.assertEqual(ua.action_type, "delete_rule_filter")
        self.assertEqual(ua.comment, "test comment")

    def test_014_threshold_create(self):
        f = {
            "filter_defs": [
                {
                    "key": "alert.signature_id",
                    "value": "1",
                    "operator": "equal",
                    "full_string": True,
                    "msg": "test rule",
                }
            ],
            "action": "threshold",
            "options": {"type": "both", "count": 2, "seconds": 30, "track": "by_src"},
            "rulesets": [self.ruleset.pk],
        }
        r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
        self._remove_filters_pk(r)
        self.assertDictContainsSubset(f, r)
        self.filter_pk = r["pk"]

    def test_016_threshold_update(self):
        self.test_014_threshold_create()
        self.http_patch(self.detail_url(self.filter_pk), {"action": "suppress", "options": {}})

    def test_017_threshold_update_invalid(self):
        self.test_014_threshold_create()
        r = self.http_patch(
            self.detail_url(self.filter_pk), {"action": "threshold", "options": {}}, status=status.HTTP_400_BAD_REQUEST
        )
        self.assertDictEqual(
            r, {"options": [{"type": ["This field is required."], "track": ["This field is required."]}]}
        )

    def test_025_intersect_match(self):
        self.test_007_order_create_append()

        conflict_filter = {
            "filter_defs": [{"key": "event_type", "value": "dns", "operator": "equal"}],
        }
        r = self.http_post(reverse("ruleprocessingfilter-intersect"), conflict_filter)
        self.assertEqual(r.get("count"), 1)
        self._remove_filters_pk(r["results"][0])
        self.assertDictContainsSubset(self.DEFAULT_FILTER, r["results"][0])

    def test_026_intersect_multi_match(self):
        self.test_007_order_create_append()

        conflict_filter = {
            "filter_defs": [
                {"key": "event_type", "value": "dns", "operator": "equal"},
                {"key": "host", "value": "test42", "operator": "contains"},
            ],
        }
        r = self.http_post(reverse("ruleprocessingfilter-intersect"), conflict_filter)
        self.assertEqual(r.get("count"), 2)

    def test_027_intersect_no_match(self):
        self.test_007_order_create_append()

        conflict_filter = {
            "filter_defs": [{"key": "alert.signature_id", "value": "dns", "operator": "equal"}],
        }
        r = self.http_post(reverse("ruleprocessingfilter-intersect"), conflict_filter)
        self.assertEqual(r.get("count"), 0)

    def test_028_create(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f["filter_defs"] = [
            {"key": "event_type", "value": "dns", "operator": "different", "full_string": True},
            {"key": "event_type", "value": "http", "operator": "different", "full_string": True},
        ]

        r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
        self._remove_filters_pk(r)
        self.assertDictContainsSubset(f, r)


def order_update_lambda(a, b):
    return lambda x: RestAPIRuleProcessingFilterTestCase._test_010_order_update(x, a, b)


for a, b in itertools.product(list(range(4)), list(range(5)) + [None]):
    setattr(
        RestAPIRuleProcessingFilterTestCase, "test_010_order_update_%i_to_%s" % (a, repr(b)), order_update_lambda(a, b)
    )
