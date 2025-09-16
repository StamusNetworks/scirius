import pytest
from django.test import TestCase
from django.utils import timezone

from rules.models.model import (
    Category,
    Rule,
    RuleAtVersion,
    Source,
    Transformation,
)


@pytest.mark.django_db
class TransformationTestCase(TestCase):
    def setUp(self):
        self.source = Source.objects.create(
            name="test source", created_date=timezone.now(), method="local", datatype="sig"
        )
        self.source.save()
        self.category = Category.objects.create(name="test category", filename="test", source=self.source)
        self.category.save()

        # Commented rule
        content = '#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Trans2 FIND_FIRST2 attempt"; \
flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB2"; within:5; distance:3; content:"|01 00|"; \
within:2; distance:56; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103141; \
rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)'

        self.rule_commented = Rule.objects.create(sid=1, category=self.category, msg="test commented rule")
        self.rule_commented.save()
        RuleAtVersion.objects.create(rule=self.rule_commented, content=content)

        # Lateral yes
        content = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP Overflow Attempt"; flow:to_server,established; \
content:"|E8 C0 FF FF FF|/bin/sh"; classtype:attempted-admin; sid:2100293; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)'

        self.rule_lateral_yes = Rule.objects.create(sid=2, category=self.category, msg="test lateral yes")
        self.rule_lateral_yes.save()
        RuleAtVersion.objects.create(rule=self.rule_lateral_yes, content=content)

        # Lateral auto
        content = 'alert dns $HOME_NET any -> any any (msg:"ET POLICY DNS Query to .onion proxy Domain (onion. sx)"; dns_query; \
content:".onion.sx"; nocase; isdataat:!1,relative; metadata: former_category POLICY; \
reference:url,en.wikipedia.org/wiki/Tor_(anonymity_network); classtype:bad-unknown; sid:2025446; rev:2; \
metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, \
deployment Perimeter, signature_severity Minor, created_at 2018_03_28, performance_impact Moderate, updated_at 2018_03_30;)'

        self.rule_lateral_auto_no_transfo = Rule.objects.create(
            sid=3, category=self.category, msg="test lateral auto => no transfo"
        )
        self.rule_lateral_auto_no_transfo.save()
        RuleAtVersion.objects.create(rule=self.rule_lateral_auto_no_transfo, content=content)

        content = (
            'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'
        )

        self.rule_lateral_auto_transfo = Rule.objects.create(
            sid=4, category=self.category, msg="test lateral auto => transfo"
        )
        self.rule_lateral_auto_transfo.save()
        RuleAtVersion.objects.create(rule=self.rule_lateral_auto_transfo, content=content)

        # Target Auto
        content = (
            'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'
        )

        self.rule_target_auto_transfo = Rule.objects.create(
            sid=5, category=self.category, msg="test target auto => transfo"
        )
        self.rule_target_auto_transfo.save()
        RuleAtVersion.objects.create(rule=self.rule_target_auto_transfo, content=content)

        content = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_CLIENT HTA File Download Flowbit Set"; \
flow:established,to_client; content:"Content-Type|3A| application/hta"; http_header; fast_pattern:12,16; flowbits:set,et.http.hta; \
flowbits:noalert; metadata: former_category WEB_CLIENT; classtype:not-suspicious; sid:2024195; rev:2; \
metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, \
signature_severity Major, created_at 2017_04_10, performance_impact Low, updated_at 2017_04_10;)'

        self.rule_target_auto_no_transfo = Rule.objects.create(
            sid=6, category=self.category, msg="test target auto => no transfo"
        )
        self.rule_target_auto_no_transfo.save()
        RuleAtVersion.objects.create(rule=self.rule_target_auto_no_transfo, content=content)

        # Target Source
        content = (
            'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'
        )

        self.rule_target_source_transfo = Rule.objects.create(
            sid=7, category=self.category, msg="test target source => transfo"
        )
        self.rule_target_source_transfo.save()
        RuleAtVersion.objects.create(rule=self.rule_target_source_transfo, content=content)

        # Target Destination
        content = (
            'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'
        )

        self.rule_target_destination_transfo = Rule.objects.create(
            sid=8, category=self.category, msg="test target destination => transfo"
        )
        self.rule_target_destination_transfo.save()
        RuleAtVersion.objects.create(rule=self.rule_target_destination_transfo, content=content)

    def tearDown(self):
        pass

    def test_001_commented_rule(self):
        content = self.rule_commented.ruleatversion_set.first().content
        content = self.rule_commented.apply_lateral_target_transfo(
            content, Transformation.LATERAL, Transformation.L_YES
        )
        self.assertEqual(self.rule_commented.ruleatversion_set.first().content, content)

    def test_002_lateral_yes(self):
        content = self.rule_lateral_yes.ruleatversion_set.first().content
        content = self.rule_lateral_yes.apply_lateral_target_transfo(
            content, key=Transformation.LATERAL, value=Transformation.L_YES
        )
        self.assertIn("alert tcp any any", content)

    def test_003_lateral_auto(self):
        # ET POLICY disbale transformation
        content = self.rule_lateral_auto_no_transfo.ruleatversion_set.first().content
        content = self.rule_lateral_auto_no_transfo.apply_lateral_target_transfo(
            content, Transformation.LATERAL, Transformation.L_AUTO
        )
        self.assertEqual(self.rule_lateral_auto_no_transfo.ruleatversion_set.first().content, content)

        # deployment Interna enable Transformation
        content = self.rule_lateral_auto_transfo.ruleatversion_set.first().content
        content = self.rule_lateral_auto_transfo.apply_lateral_target_transfo(
            content, Transformation.LATERAL, Transformation.L_AUTO
        )
        self.assertIn("alert tcp any any", content)

    def test_004_target_auto(self):
        # attack_target enable transformation
        content = self.rule_target_auto_transfo.ruleatversion_set.first().content
        content = self.rule_target_auto_transfo.apply_lateral_target_transfo(
            content, Transformation.TARGET, Transformation.T_AUTO
        )
        self.assertTrue(content.endswith("target:dest_ip;)"))

        # attack_target enable transformation
        # but not-suspicious disable it
        content = self.rule_target_auto_no_transfo.ruleatversion_set.first().content
        content = self.rule_target_auto_no_transfo.apply_lateral_target_transfo(
            content, Transformation.TARGET, Transformation.T_AUTO
        )
        self.assertEqual(self.rule_target_auto_no_transfo.ruleatversion_set.first().content, content)

    def test_005_target_source(self):
        # attack_target enable transformation
        content = self.rule_target_source_transfo.ruleatversion_set.first().content
        content = self.rule_target_source_transfo.apply_lateral_target_transfo(
            content, Transformation.TARGET, Transformation.T_SOURCE
        )
        self.assertTrue(content.endswith("target:src_ip;)"))

    def test_005_target_destination(self):
        # attack_target enable transformation
        content = self.rule_target_destination_transfo.ruleatversion_set.first().content
        content = self.rule_target_destination_transfo.apply_lateral_target_transfo(
            content, Transformation.TARGET, Transformation.T_DESTINATION
        )
        self.assertTrue(content.endswith("target:dest_ip;)"))
