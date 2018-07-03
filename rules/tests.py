"""
Copyright(C) 2014, Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
"""

import json
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.test import TestCase
from django.utils import timezone
from rest_framework import status, mixins
from rest_framework.test import APITestCase

from models import Category, Rule, Ruleset, Source, SourceAtVersion, Transformation, RuleTransformation, \
    RulesetTransformation, SourceUpdate, SystemSettings, UserAction, RuleProcessingFilter, RuleProcessingFilterDef
from rest_api import router

from copy import deepcopy
import tempfile
from shutil import rmtree
from StringIO import StringIO
import itertools
from importlib import import_module


ET_URL = 'https://rules.emergingthreats.net/open/suricata-2.0.1/emerging.rules.tar.gz'


class SourceCreationTestCase(TestCase):
    def setUp(self):
        self.tmpdirname = tempfile.mkdtemp()
        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            self.source = Source.objects.create(name="ET Open",
                                       method = "http",
                                       datatype = "sigs",
                                       uri=ET_URL,
                                       created_date=timezone.now())

    def tearDown(self):
        rmtree(self.tmpdirname)

    def test_source_update(self):
        """Test source update"""
        self.source.update()
        self.assertEqual(len(SourceAtVersion.objects.filter(source = self.source)), 1)
        self.assertNotEqual(len(Category.objects.filter(source = self.source)), 0)


class TransformationTestCase(TestCase):
    def setUp(self):
        self.source = Source.objects.create(name='test source', created_date=timezone.now(), method='local', datatype='sig')
        self.source.save()
        self.source_at_version = SourceAtVersion.objects.create(source=self.source, version='42')
        self.source_at_version.save()
        self.category = Category.objects.create(name='test category', filename='test', source=self.source)
        self.category.save()

        # Commented rule
        content = '#alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Trans2 FIND_FIRST2 attempt"; \
flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMB2"; within:5; distance:3; content:"|01 00|"; \
within:2; distance:56; flowbits:set,smb.trans2; flowbits:noalert; classtype:protocol-command-decode; sid:2103141; \
rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)'

        self.rule_commented = Rule.objects.create(sid=1, category=self.category, msg='test commented rule', content=content)
        self.rule_commented.save()

        # Lateral yes
        content = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP Overflow Attempt"; flow:to_server,established; \
content:"|E8 C0 FF FF FF|/bin/sh"; classtype:attempted-admin; sid:2100293; rev:8; metadata:created_at 2010_09_23, updated_at 2010_09_23;)'

        self.rule_lateral_yes = Rule.objects.create(sid=2, category=self.category, msg='test lateral yes', content=content)
        self.rule_lateral_yes.save()

        # Lateral auto
        content = 'alert dns $HOME_NET any -> any any (msg:"ET POLICY DNS Query to .onion proxy Domain (onion. sx)"; dns_query; \
content:".onion.sx"; nocase; isdataat:!1,relative; metadata: former_category POLICY; \
reference:url,en.wikipedia.org/wiki/Tor_(anonymity_network); classtype:bad-unknown; sid:2025446; rev:2; \
metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, \
deployment Perimeter, signature_severity Minor, created_at 2018_03_28, performance_impact Moderate, updated_at 2018_03_30;)'

        self.rule_lateral_auto_no_transfo = Rule.objects.create(sid=3, category=self.category, msg='test lateral auto => no transfo', content=content)
        self.rule_lateral_auto_no_transfo.save()

        content = 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'

        self.rule_lateral_auto_transfo = Rule.objects.create(sid=4, category=self.category, msg='test lateral auto => transfo', content=content)
        self.rule_lateral_auto_transfo.save()

        # Target Auto
        content = 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'

        self.rule_target_auto_transfo = Rule.objects.create(sid=5, category=self.category, msg='test target auto => transfo', content=content)
        self.rule_target_auto_transfo.save()

        content = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_CLIENT HTA File Download Flowbit Set"; \
flow:established,to_client; content:"Content-Type|3A| application/hta"; http_header; fast_pattern:12,16; flowbits:set,et.http.hta; \
flowbits:noalert; metadata: former_category WEB_CLIENT; classtype:not-suspicious; sid:2024195; rev:2; \
metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, \
signature_severity Major, created_at 2017_04_10, performance_impact Low, updated_at 2017_04_10;)'

        self.rule_target_auto_no_transfo = Rule.objects.create(sid=6, category=self.category, msg='test target auto => no transfo', content=content)
        self.rule_target_auto_no_transfo.save()

        # Target Source
        content = 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'

        self.rule_target_source_transfo = Rule.objects.create(sid=7, category=self.category, msg='test target source => transfo', content=content)
        self.rule_target_source_transfo.save()

        # Target Destination
        content = 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'

        self.rule_target_destination_transfo = Rule.objects.create(sid=8, category=self.category, msg='test target destination => transfo', content=content)
        self.rule_target_destination_transfo.save()

    def tearDown(self):
        pass

    def test_001_commented_rule(self):
        content = self.rule_commented.apply_lateral_target_transfo(self.rule_commented.content, Transformation.LATERAL, Transformation.L_YES)
        self.assertEqual(self.rule_commented.content, content)

    def test_002_lateral_yes(self):
        content = self.rule_lateral_yes.apply_lateral_target_transfo(self.rule_lateral_yes.content, key=Transformation.LATERAL, value=Transformation.L_YES)
        self.assertEqual('alert tcp any any' in content, True)

    def test_003_lateral_auto(self):
        # ET POLICY disbale transformation
        content = self.rule_lateral_auto_no_transfo.apply_lateral_target_transfo(self.rule_lateral_auto_no_transfo.content, Transformation.LATERAL, Transformation.L_AUTO)
        self.assertEqual(self.rule_lateral_auto_no_transfo.content, content)

        # deployment Interna enable Transformation
        content = self.rule_lateral_auto_transfo.apply_lateral_target_transfo(self.rule_lateral_auto_transfo.content, Transformation.LATERAL, Transformation.L_AUTO)
        self.assertEqual('alert tcp any any' in content, True)

    def test_004_target_auto(self):
        # attack_target enable transformation
        content = self.rule_target_auto_transfo.apply_lateral_target_transfo(self.rule_target_auto_transfo.content, Transformation.TARGET, Transformation.T_AUTO)
        self.assertEqual(content.endswith('target:dest_ip;)'), True)

        # attack_target enable transformation
        # but not-suspicious disable it
        content = self.rule_target_auto_no_transfo.apply_lateral_target_transfo(self.rule_target_auto_no_transfo.content, Transformation.TARGET, Transformation.T_AUTO)
        self.assertEqual(self.rule_target_auto_no_transfo.content, content)

    def test_005_target_source(self):
        # attack_target enable transformation
        content = self.rule_target_source_transfo.apply_lateral_target_transfo(self.rule_target_source_transfo.content, Transformation.TARGET, Transformation.T_SOURCE)
        self.assertEqual(content.endswith('target:src_ip;)'), True)

    def test_005_target_destination(self):
        # attack_target enable transformation
        content = self.rule_target_destination_transfo.apply_lateral_target_transfo(self.rule_target_destination_transfo.content, Transformation.TARGET, Transformation.T_DESTINATION)
        self.assertEqual(content.endswith('target:dest_ip;)'), True)


class RestAPITestBase(object):
    def setUp(self):
        self.user = User.objects.create(username='scirius', password='scirius', is_superuser=True, is_staff=True)
        self.client.force_login(self.user)

    def _make_request(self, method, url, *args, **kwargs):
        func = getattr(self.client, method)
        http_status = kwargs.pop('status', status.HTTP_200_OK)

        if 'format' not in kwargs:
            kwargs['format'] = 'json'
        try:
            response = func(url, *args, **kwargs)
        except Exception as e:
            if len(e.args) >= 1:
                msg = 'Request failure on %s:\n%s' % (url, e.args[0])
                e.args = (msg,) + e.args[1:]
            raise

        # behavior/status could be different on remote and local build
        try:
            data_msg = unicode(getattr(response, 'data', None))
        except UnicodeDecodeError:
            data_msg = repr(getattr(response, 'data', None))
        msg = 'Request failed: \n%s %s\n%s %s\n%s' % (method.upper(), url, response.status_code, response.reason_phrase, data_msg)

        if isinstance(http_status, tuple):
            self.assertEqual(response.status_code in http_status, True, msg)
            return getattr(response, 'data', None), response.status_code
        else:
            self.assertEqual(response.status_code, http_status, msg)

        return getattr(response, 'data', None)

    http_get = lambda self, *args, **kwargs: self._make_request('get', *args, **kwargs)
    http_post = lambda self, *args, **kwargs: self._make_request('post', *args, **kwargs)
    http_put = lambda self, *args, **kwargs: self._make_request('put', *args, **kwargs)
    http_patch = lambda self, *args, **kwargs: self._make_request('patch', *args, **kwargs)
    http_delete = lambda self, *args, **kwargs: self._make_request('delete', *args, **kwargs)
    http_options = lambda self, *args, **kwargs: self._make_request('options', *args, **kwargs)


class RestAPISourceTestCase(RestAPITestBase, APITestCase):
    RULE_CONTENT = 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Metasploit Meterpreter stdapi_* Command Request"; \
flow:established; content:"|00 01 00 01|stdapi_"; offset:12; depth:11;  classtype:successful-user; sid:2014530; rev:3; \
metadata:affected_product Any, attack_target Client_and_Server, deployment Perimeter, deployment Internet, deployment Internal, \
deployment Datacenter, tag Metasploit, signature_severity Critical, created_at 2012_04_06, updated_at 2016_07_01;)'

    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.ruleset = Ruleset.objects.create(name='test ruleset', descr='descr', created_date=timezone.now(), updated_date=timezone.now())
        self.ruleset.save()

    def _create_public_source(self):
        params = {
                'name': 'sonic test public source',
                'comment': 'MyPublicComment',
                'public_source': 'oisf/trafficid',
                }
        self.http_post(reverse('publicsource-list'), params, status=status.HTTP_201_CREATED)
        sources = Source.objects.filter(name='sonic test public source')
        self.assertEqual(len(sources) == 1, True)

        sources_at_version = SourceAtVersion.objects.filter(source=sources[0])
        self.assertEqual(len(sources_at_version) == 1, True)

        self.assertEqual(sources_at_version[0].source == sources[0], True)

        self.public_source = sources[0]
        self.ruleset.sources.add(sources_at_version[0])

    def _create_custom_source(self, method, datatype, **kwargs):
        params = {
            'name': 'sonic test custom source',
            'comment': 'MyCustomComment',
            'method': method,
            'datatype':  datatype
        }
        params.update(kwargs)
        self.http_post(reverse('source-list'), params, status=status.HTTP_201_CREATED)
        sources = Source.objects.filter(name='sonic test custom source')
        self.assertEqual(len(sources) == 1, True)

        sources_at_version = SourceAtVersion.objects.filter(source=sources[0])
        self.assertEqual(len(sources_at_version) == 1, True)

        self.assertEqual(sources_at_version[0].source == sources[0], True)

        self.source = sources[0]
        self.ruleset.sources.add(sources_at_version[0])

    def test_001_public_source(self):
        self._create_public_source()
        response = self.http_get(reverse('publicsource-fetch-list-sources'))
        self.assertDictEqual(response, {'fetch': 'ok'})

        response = self.http_post(reverse('publicsource-update-source', args=(self.public_source.pk,)))
        self.assertDictEqual(response, {'update': 'ok'})

        # behavior/status could be different on remote and local build
        status_ = (status.HTTP_400_BAD_REQUEST, status.HTTP_200_OK)
        response, status_ = self.http_post(reverse('publicsource-test', args=(self.public_source.pk,)), status=status_)

        if status_ == status.HTTP_400_BAD_REQUEST:
            self.assertEqual('errors' in response['test'], True)
        else:
            self.assertEqual(status_, status.HTTP_200_OK)
            self.assertEqual('test' in response and response['test'] == 'ok', True)

            self.http_get(reverse('publicsource-list-sources'))

        response = self.http_delete(reverse('publicsource-detail', args=(self.public_source.pk,)), status=status.HTTP_204_NO_CONTENT)
        sources = Source.objects.filter(pk=self.public_source.pk)
        self.assertEqual(len(sources), 0)

    def test_002_custom_source_upload(self):
        self._create_custom_source('local', 'sig')
        response = self.http_post(reverse('source-upload', args=(self.source.pk,)), {'file': StringIO(self.RULE_CONTENT)}, format='multipart')
        self.assertDictEqual(response, {'upload': 'ok'})

        response = self.http_post(reverse('source-update-source', args=(self.source.pk,)))
        self.assertDictEqual(response, {'update': 'ok'})

        response = self.http_get(reverse('category-list') + '?source=%i' % self.source.pk)
        categories = response.get('results', [])
        self.assertEqual(len(categories), 1)

        response = self.http_get(reverse('rule-list') + '?category=%i' % categories[0]['pk'])
        rules = response.get('results', [])
        self.assertEqual(len(rules), 1)

        rule = rules[0]
        self.assertDictContainsSubset({
            'sid': 2014530,
            'msg': 'ET TROJAN Metasploit Meterpreter stdapi_* Command Request',
            'state': True,
            'state_in_source': True,
            'content': self.RULE_CONTENT,
            'rev': 3
        }, rule)

    def test_003_custom_source_bad_upload(self):
        self._create_custom_source('local', 'sigs')

        with open('/usr/bin/find', 'rb') as f:
            response = self.http_post(reverse('source-upload', args=(self.source.pk,)), {'file': f}, format='multipart', status=status.HTTP_400_BAD_REQUEST)
            self.assertDictEqual(response, {'upload': ['Invalid tar file']})

        response = self.http_delete(reverse('source-detail', args=(self.source.pk,)), status=status.HTTP_204_NO_CONTENT)
        sources = Source.objects.filter(pk=self.source.pk)
        self.assertEqual(len(sources), 0)

    def test_004_custom_source_http(self):
        self._create_custom_source('http', 'sigs', uri=ET_URL, cert_verif=True)

        response = self.http_post(reverse('source-update-source', args=(self.source.pk,)))
        self.assertDictEqual(response, {'update': 'ok'})

    def test_005_custom_source_bad_http(self):
        self._create_custom_source('http', 'sigs', uri='http://localhost:1234/')

        response = self.http_post(reverse('source-update-source', args=(self.source.pk,)), status=status.HTTP_400_BAD_REQUEST)
        msg = str(response.get('update', [''])[0])
        self.assertRegexpMatches(msg, 'Can not fetch data: .* Connection refused')

    def test_006_custom_source_delete(self):
        self._create_custom_source('local', 'sig')
        self.http_delete(reverse('source-detail', args=(self.source.pk,)), {'comment': 'source delete'}, status=status.HTTP_204_NO_CONTENT)

        ua = UserAction.objects.order_by('pk').last()
        self.assertEqual(ua.action_type, 'delete_source')
        self.assertEqual(ua.comment, 'source delete')


class RestAPIRulesetTransformationTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.source = Source.objects.create(name='test source', created_date=timezone.now(), method='local', datatype='sig')
        self.source.save()
        self.source_at_version = SourceAtVersion.objects.create(source=self.source, version='42')
        self.source_at_version.save()

        self.category = Category.objects.create(name='test category', filename='test', source=self.source)
        self.category.save()

        self.rule = Rule.objects.create(sid=1, category=self.category, msg='test rule', content='')
        self.rule.save()

        self.ruleset = Ruleset.objects.create(name='test ruleset', descr='descr', created_date=timezone.now(), updated_date=timezone.now())
        self.ruleset.save()
        self.ruleset.sources.add(self.source_at_version)
        self.ruleset.categories.add(self.category)

    def test_001_ruleset_transformations(self):
        params = {"ruleset": self.ruleset.pk, "transfo_type": "action", "transfo_value": "reject"}
        self.http_post(reverse('rulesettransformation-list'), params, status=status.HTTP_201_CREATED)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "lateral", "transfo_value": "yes"}
        self.http_post(reverse('rulesettransformation-list'), params, status=status.HTTP_201_CREATED)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "target", "transfo_value": "src"}
        self.http_post(reverse('rulesettransformation-list'), params, status=status.HTTP_201_CREATED)

        # Create Ruleset Transformation
        action_trans = RulesetTransformation.objects.filter(key='action')
        self.assertEqual(len(action_trans) == 1, True)
        self.assertEqual(action_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(action_trans[0].key == 'action', True)
        self.assertEqual(action_trans[0].value == 'reject', True)

        lateral_trans = RulesetTransformation.objects.filter(key='lateral')
        self.assertEqual(lateral_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(lateral_trans[0].key == 'lateral', True)
        self.assertEqual(lateral_trans[0].value == 'yes', True)

        target_trans = RulesetTransformation.objects.filter(key='target')
        self.assertEqual(target_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(target_trans[0].key == 'target', True)
        self.assertEqual(target_trans[0].value == 'src', True)

        # PATCH Ruleset Transformation
        params = {"ruleset": self.ruleset.pk, "transfo_type": "action", "transfo_value": "drop"}
        self.http_patch(reverse('rulesettransformation-detail', args=(action_trans[0].pk,)), params)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "lateral", "transfo_value": "auto"}
        self.http_patch(reverse('rulesettransformation-detail', args=(lateral_trans[0].pk,)), params)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "target", "transfo_value": "dst"}
        self.http_patch(reverse('rulesettransformation-detail', args=(target_trans[0].pk,)), params)

        action_trans = RulesetTransformation.objects.filter(key='action')
        self.assertEqual(action_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(action_trans[0].key == 'action', True)
        self.assertEqual(action_trans[0].value == 'drop', True)

        lateral_trans = RulesetTransformation.objects.filter(key='lateral')
        self.assertEqual(lateral_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(lateral_trans[0].key == 'lateral', True)
        self.assertEqual(lateral_trans[0].value == 'auto', True)

        target_trans = RulesetTransformation.objects.filter(key='target')
        self.assertEqual(target_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(target_trans[0].key == 'target', True)
        self.assertEqual(target_trans[0].value == 'dst', True)

        # PUT Ruleset Transformation
        params = {"ruleset": self.ruleset.pk, "transfo_type": "action", "transfo_value": "filestore"}
        self.http_put(reverse('rulesettransformation-detail', args=(action_trans[0].pk,)), params)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "lateral", "transfo_value": "yes"}
        self.http_put(reverse('rulesettransformation-detail', args=(lateral_trans[0].pk,)), params)

        params = {"ruleset": self.ruleset.pk, "transfo_type": "target", "transfo_value": "auto"}
        self.http_put(reverse('rulesettransformation-detail', args=(target_trans[0].pk,)), params)

        action_trans = RulesetTransformation.objects.filter(key='action')
        self.assertEqual(action_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(action_trans[0].key == 'action', True)
        self.assertEqual(action_trans[0].value == 'filestore', True)

        lateral_trans = RulesetTransformation.objects.filter(key='lateral')
        self.assertEqual(lateral_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(lateral_trans[0].key == 'lateral', True)
        self.assertEqual(lateral_trans[0].value == 'yes', True)

        target_trans = RulesetTransformation.objects.filter(key='target')
        self.assertEqual(target_trans[0].ruleset_transformation == self.ruleset, True)
        self.assertEqual(target_trans[0].key == 'target', True)
        self.assertEqual(target_trans[0].value == 'auto', True)

        # Delete
        self.http_delete(reverse('rulesettransformation-detail', args=(action_trans[0].pk,)), status=status.HTTP_204_NO_CONTENT)
        self.http_delete(reverse('rulesettransformation-detail', args=(lateral_trans[0].pk,)), status=status.HTTP_204_NO_CONTENT)
        self.http_delete(reverse('rulesettransformation-detail', args=(target_trans[0].pk,)), status=status.HTTP_204_NO_CONTENT)
        rulesets = RulesetTransformation.objects.all()
        self.assertEqual(len(rulesets), 0)


class RestAPIRulesetTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.source = Source.objects.create(name='test source', created_date=timezone.now(), method='local', datatype='sig')
        self.source.save()
        self.source_at_version = SourceAtVersion.objects.create(source=self.source, version='42')
        self.source_at_version.save()

        self.source2 = Source.objects.create(name='test source 2', created_date=timezone.now(), method='local', datatype='sig')
        self.source2.save()
        self.source_at_version2 = SourceAtVersion.objects.create(source=self.source2, version='69')
        self.source_at_version2.save()

        self.category = Category.objects.create(name='test category', filename='test', source=self.source)
        self.category.save()

        self.rule = Rule.objects.create(sid=1, category=self.category, msg='test rule', content='')
        self.rule.save()

    def test_001_ruleset_actions(self):
        params = {"name": "MyCreatedRuleset",
                  "comment": "My custom ruleset comment",
                  "sources": [self.source.pk, self.source2.pk],
                  "categories": [self.category.pk]}

        # Create Ruleset
        self.http_post(reverse('ruleset-list'), params, status=status.HTTP_201_CREATED)
        rulesets = Ruleset.objects.all()
        sources_at_version = rulesets[0].sources.all()

        self.assertEqual(len(rulesets), 1)
        self.assertEqual(rulesets[0].name, "MyCreatedRuleset")
        self.assertEqual(len(rulesets[0].categories.all()) > 0, True)
        self.assertEqual(len(sources_at_version) == 2, True)

        for src in sources_at_version:
            self.assertEqual(src in [self.source_at_version, self.source_at_version2], True)

        # PUT/PATCH Ruleset
        for idx, request in enumerate((self.http_put, self.http_patch)):
            params['name'] = 'MyRenamedCreatedRuleset%s' % idx

            status_ = status.HTTP_200_OK
            if request == self.http_patch:
                params['sources'] = []
                status_ = status.HTTP_400_BAD_REQUEST

            request(reverse('ruleset-detail', args=(rulesets[0].pk,)), params, status=status_)

            status_ = status.HTTP_200_OK
            if request == self.http_patch:
                del params['sources']
                status_ = status.HTTP_400_BAD_REQUEST

            request(reverse('ruleset-detail', args=(rulesets[0].pk,)), params, status=status.HTTP_200_OK)

            rulesets = Ruleset.objects.all()
            self.assertEqual(len(rulesets), 1)
            self.assertEqual(rulesets[0].name, "MyRenamedCreatedRuleset%s" % idx)

            self.assertEqual(len(rulesets[0].sources.all()) == 2, True)

        # Delete
        rulesets = Ruleset.objects.all()
        self.assertEqual(len(rulesets), 1)
        self.http_delete(reverse('ruleset-detail', args=(rulesets[0].pk,)), status=status.HTTP_204_NO_CONTENT)
        rulesets = Ruleset.objects.all()
        self.assertEqual(len(rulesets), 0)

    def test_002_create_ruleset_source_wrong_category(self):
        params = {"name": "MyCreatedRuleset",
                  "comment": "My custom ruleset comment",
                  "sources": [self.source2.pk],
                  "categories": [self.category.pk]}

        self.http_post(reverse('ruleset-list'), params, status=status.HTTP_400_BAD_REQUEST)

    def test_003_create_ruleset_no_source_categories(self):
        params = {"name": "MyCreatedRuleset",
                  "comment": "My custom ruleset comment",
                  "categories": [self.category.pk]}

        self.http_post(reverse('ruleset-list'), params, status=status.HTTP_400_BAD_REQUEST)

    def test_004_create_ruleset_sources_categories(self):
        params = {"name": "MyCreatedRuleset",
                  "comment": "My custom ruleset comment",
                  "sources": [self.source.pk],
                  "categories": [self.category.pk]}

        self.http_post(reverse('ruleset-list'), params, status=status.HTTP_201_CREATED)

    def test_005_update_ruleset_source_wrong_category(self):
        params = {"name": "MyCreatedRuleset",
                  "comment": "My custom ruleset comment",
                  "sources": [self.source.pk],
                  "categories": [self.category.pk]}

        # Create valid Ruleset
        self.http_post(reverse('ruleset-list'), params, status=status.HTTP_201_CREATED)
        rulesets = Ruleset.objects.all()
        self.assertEqual(len(rulesets), 1)

        # PUT/PATCH
        params["sources"] = [self.source2.pk]
        for idx, request in enumerate((self.http_put, self.http_patch)):
            params['name'] = 'MyRenamedCreatedRuleset%s' % idx
            request(reverse('ruleset-detail', args=(rulesets[0].pk,)), params, status=status.HTTP_400_BAD_REQUEST)

    def test_006_update_ruleset_no_source_categories(self):
        params = {"name": "MyCreatedRuleset",
                  "comment": "My custom ruleset comment",
                  "sources": [self.source.pk],
                  "categories": [self.category.pk]}

        # Create valid Ruleset
        self.http_post(reverse('ruleset-list'), params, status=status.HTTP_201_CREATED)
        rulesets = Ruleset.objects.all()
        self.assertEqual(len(rulesets), 1)

        # PUT/PATCH
        params.pop("sources")
        for idx, request in enumerate((self.http_put, self.http_patch)):
            params['name'] = 'MyRenamedCreatedRuleset%s' % idx

            # 200 because category is linked to source which is already in DB
            request(reverse('ruleset-detail', args=(rulesets[0].pk,)), params, status=status.HTTP_200_OK)

    def test_007_update_ruleset_sources_categories(self):
        params = {"name": "MyCreatedRuleset",
                  "comment": "My custom ruleset comment",
                  "sources": [self.source.pk],
                  "categories": [self.category.pk]}

        # Create valid Ruleset
        self.http_post(reverse('ruleset-list'), params, status=status.HTTP_201_CREATED)
        rulesets = Ruleset.objects.all()
        self.assertEqual(len(rulesets), 1)

        # PUT/PATCH
        for idx, request in enumerate((self.http_put, self.http_patch)):
            params['name'] = 'MyRenamedCreatedRuleset%s' % idx
            request(reverse('ruleset-detail', args=(rulesets[0].pk,)), params, status=status.HTTP_200_OK)

    def test_008_copy_ruleset(self):
        params = {"name": "MyCreatedRuleset",
                  "comment": "My custom ruleset comment",
                  "sources": [self.source.pk, self.source2.pk],
                  "categories": [self.category.pk]}

        # Create Ruleset
        response = self.http_post(reverse('ruleset-list'), params, status=status.HTTP_201_CREATED)
        ruleset = Ruleset.objects.get(pk=response['pk'])

        params = {'name': 'MyCreatedRulesetCopy'}
        self.http_post(reverse('ruleset-copy', args=(response['pk'],)), params, status=status.HTTP_200_OK)

        ruleset_copy = Ruleset.objects.filter(name='MyCreatedRulesetCopy')[0]
        self.assertNotEqual(ruleset.pk, ruleset_copy.pk)
        self.assertEqual(len(ruleset.sources.all()), len(ruleset_copy.sources.all()))
        self.assertEqual(len(ruleset.categories.all()), len(ruleset_copy.categories.all()))


class RestAPIRuleTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.source = Source.objects.create(name='test source', created_date=timezone.now(),
                method='local', datatype='sig')
        self.source.save()
        self.source_at_version = SourceAtVersion.objects.create(source=self.source, version='42')
        self.source_at_version.save()
        self.category = Category.objects.create(name='test category', filename='test',
                source=self.source)
        self.category.save()

        content = 'alert ip $HOME_NET any -> [103.207.29.161,103.207.29.171,103.225.168.222,103.234.36.190,103.234.37.4,103.4.164.34, \
103.6.207.37,104.131.93.109,104.140.137.152,104.143.5.144,104.144.167.131,104.144.167.251,104.194.206.108, \
104.199.121.36,104.207.154.26,104.223.87.207,104.43.200.222,106.187.48.236,107.161.19.71] \
any (msg:"ET CNC Shadowserver Reported CnC Server IP group 1"; \
reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,www.shadowserver.org;\
threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; \
flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404000; rev:4933;)'

        self.rule = Rule.objects.create(sid=1, category=self.category, msg='test rule',
                content=content)
        self.rule.save()
        self.ruleset = Ruleset.objects.create(name='test ruleset', descr='descr', created_date=timezone.now(),
                updated_date=timezone.now())
        self.ruleset.save()
        self.ruleset.sources.add(self.source_at_version)
        self.ruleset.categories.add(self.category)

    def test_001_rule_detail(self):
        self.http_get(reverse('rule-detail', args=(self.rule.pk,)))

    def test_002_rule_disable(self):
        self.http_post(reverse('rule-disable', args=(self.rule.pk,)), {'ruleset': self.ruleset.pk})
        self.ruleset.refresh_from_db()

        disabled = self.ruleset.get_transformed_rules(key=Transformation.SUPPRESSED, value=Transformation.S_SUPPRESSED)
        self.assertEqual(len(disabled), 1)
        self.assertEqual(disabled[0].pk, self.rule.pk)

        self.http_post(reverse('rule-enable', args=(self.rule.pk,)), {'ruleset': self.ruleset.pk})
        self.ruleset.refresh_from_db()

        disabled = self.ruleset.get_transformed_rules(key=Transformation.SUPPRESSED, value=Transformation.S_SUPPRESSED)
        self.assertEqual(len(disabled), 0)

    def test_003_rule_permission(self):
        self.client.logout()

        # Non logged request are rejected
        self.http_post(reverse('rule-disable', args=(self.rule.pk,)), {'ruleset': self.ruleset.pk},
                status=status.HTTP_403_FORBIDDEN)

        # Post not authorized non-staff
        self.user.is_superuser = False
        self.user.is_staff = False
        self.user.save()
        self.client.force_login(self.user)
        # Read still authorized
        self.http_post(reverse('rule-disable', args=(self.rule.pk,)), {'ruleset': self.ruleset.pk},
                status=status.HTTP_403_FORBIDDEN)

    def test_004_rule_transformation(self):
        # Transform ruleset
        self.http_post(reverse('rulesettransformation-list'),
                       {'ruleset': self.ruleset.pk,
                           'transfo_type': Transformation.ACTION.value,
                           'transfo_value': Transformation.A_FILESTORE.value},
                       status=status.HTTP_201_CREATED)

        # Check inheritance on category
        transformation = self.category.get_transformation(ruleset=self.ruleset, key=Transformation.ACTION, override=True)
        self.assertEqual(transformation, Transformation.A_FILESTORE)

        # Check inheritance on rule
        transformation = self.rule.get_transformation(ruleset=self.ruleset, key=Transformation.ACTION, override=True)
        self.assertEqual(transformation, Transformation.A_FILESTORE)

        # Transform Category
        self.http_post(reverse('categorytransformation-list'),
                       {'category': self.category.pk, 'ruleset': self.ruleset.pk,
                           'transfo_type': Transformation.ACTION.value,
                           'transfo_value': Transformation.A_DROP.value},
                       status=status.HTTP_201_CREATED)

        # Check category transformation
        transformation = self.category.get_transformation(ruleset=self.ruleset, key=Transformation.ACTION)
        self.assertEqual(transformation, Transformation.A_DROP)

        # Check inheritance on rule (from category)
        transformation = self.rule.get_transformation(ruleset=self.ruleset, key=Transformation.ACTION, override=True)
        self.assertEqual(transformation, Transformation.A_DROP)

        # Transform rule
        self.http_post(reverse('ruletransformation-list'),
                       {'rule': self.rule.pk, 'ruleset': self.ruleset.pk,
                           'transfo_type': Transformation.ACTION.value,
                           'transfo_value': Transformation.A_REJECT.value},
                       status=status.HTTP_201_CREATED)

        # Check transformed rule
        transformed = self.ruleset.get_transformed_rules(key=Transformation.ACTION, value=Transformation.A_REJECT)
        self.assertEqual(len(transformed), 1)
        self.assertEqual(transformed[0].pk, self.rule.pk)

        transformation = self.rule.get_transformation(ruleset=self.ruleset, key=Transformation.ACTION)
        self.assertEqual(transformation, Transformation.A_REJECT)

        # Transform same rule
        self.ruletransformation = RuleTransformation.objects.filter(rule_transformation=self.rule, ruleset=self.ruleset)
        self.http_patch(reverse('ruletransformation-detail',  args=(self.ruletransformation[0].pk,)),
                        {'rule': self.rule.pk, 'ruleset': self.ruleset.pk,
                            'transfo_type': Transformation.ACTION.value,
                            'transfo_value': Transformation.A_DROP.value})

        transformed = self.ruleset.get_transformed_rules(key=Transformation.ACTION, value=Transformation.A_REJECT)
        self.assertEqual(len(transformed), 0)

    def test_005_rule_transformation_content(self):
        self.http_post(reverse('rulesettransformation-list'),
                       {'ruleset': self.ruleset.pk,
                           'transfo_type': Transformation.ACTION.value,
                           'transfo_value': Transformation.A_DROP.value},
                       status=status.HTTP_201_CREATED)

        content = self.http_get(reverse('rule-content', args=(self.rule.pk,)))
        self.assertEqual(u'drop' in content[self.ruleset.pk], True)

        self.http_post(reverse('categorytransformation-list'),
                       {'category': self.category.pk, 'ruleset': self.ruleset.pk,
                           'transfo_type': Transformation.ACTION.value,
                           'transfo_value': Transformation.A_REJECT.value},
                       status=status.HTTP_201_CREATED)

        content = self.http_get(reverse('rule-content', args=(self.rule.pk,)))
        self.assertEqual(u'reject' in content[self.ruleset.pk], True)

        self.http_post(reverse('ruletransformation-list'),
                       {'rule': self.rule.pk, 'ruleset': self.ruleset.pk,
                           'transfo_type': Transformation.ACTION.value,
                           'transfo_value': Transformation.A_DROP.value},
                       status=status.HTTP_201_CREATED)

        content = self.http_get(reverse('rule-content', args=(self.rule.pk,)))
        self.assertEqual(u'drop' in content[self.ruleset.pk], True)

    def test_006_rule_status(self):
        self.http_post(reverse('rulesettransformation-list'),
                       {'ruleset': self.ruleset.pk,
                           'transfo_type': Transformation.ACTION.value,
                           'transfo_value': Transformation.A_DROP.value},
                       status=status.HTTP_201_CREATED)

        status_ = self.http_get(reverse('rule-status', args=(self.rule.pk,)))
        self.assertTrue(self.ruleset.pk in status_)
        self.assertEqual(status_[self.ruleset.pk]['transformations']['action'], 'drop')

        self.http_post(reverse('categorytransformation-list'),
                       {'category': self.category.pk, 'ruleset': self.ruleset.pk,
                           'transfo_type': Transformation.ACTION.value,
                           'transfo_value': Transformation.A_REJECT.value},
                       status=status.HTTP_201_CREATED)

        status_ = self.http_get(reverse('rule-status', args=(self.rule.pk,)))
        self.assertTrue(self.ruleset.pk in status_)
        self.assertEqual(status_[self.ruleset.pk]['transformations']['action'], 'reject')

    def test_007_rule_toggle_availability(self):
        self.http_post(reverse('rule-toggle-availability', args=(self.rule.pk,)), {}, status=status.HTTP_200_OK)
        rule = Rule.objects.get(pk=self.rule.pk)
        self.assertEqual(rule.state, False)

        self.http_post(reverse('rule-toggle-availability', args=(self.rule.pk,)), {}, status=status.HTTP_200_OK)
        rule = Rule.objects.get(pk=self.rule.pk)
        self.assertEqual(rule.state, True)

    def test_008_rule_comment(self):
        comment = 'Need a comment for my test.'
        self.http_post(reverse('rule-comment', args=(self.rule.pk,)), {'comment': comment})

        ua = UserAction.objects.order_by('pk').last()
        self.assertEqual(ua.comment, comment)

    def test_009_get_transformed_rules(self):
        # Transform ruleset
        self.http_post(reverse('rulesettransformation-list'),
                       {'ruleset': self.ruleset.pk,
                           'transfo_type': Transformation.ACTION.value,
                           'transfo_value': Transformation.A_REJECT.value},
                       status=status.HTTP_201_CREATED)
        params = '?transfo_type=%s&transfo_value=%s' % (Transformation.ACTION.value, Transformation.A_REJECT.value)
        content = self.http_get(reverse('rule-transformation') + params)

        self.assertEqual(self.ruleset.pk in content, True)
        self.assertEqual(content[self.ruleset.pk]['rules'][0], self.rule.pk)
        self.assertEqual(content[self.ruleset.pk]['transformation']['transfo_key'], Transformation.ACTION.value)
        self.assertEqual(content[self.ruleset.pk]['transformation']['transfo_value'], Transformation.A_REJECT.value)

        self.http_post(reverse('categorytransformation-list'),
                       {'ruleset': self.ruleset.pk, 'category': self.category.pk,
                           'transfo_type': Transformation.ACTION.value,
                           'transfo_value': Transformation.A_DROP.value},
                       status=status.HTTP_201_CREATED)
        params = '?transfo_type=%s&transfo_value=%s' % (Transformation.ACTION.value, Transformation.A_DROP.value)
        content = self.http_get(reverse('rule-transformation') + params)

        self.assertEqual(self.ruleset.pk in content, True)
        self.assertEqual(content[self.ruleset.pk]['rules'][0], self.rule.pk)
        self.assertEqual(content[self.ruleset.pk]['transformation']['transfo_key'], Transformation.ACTION.value)
        self.assertEqual(content[self.ruleset.pk]['transformation']['transfo_value'], Transformation.A_DROP.value)

        self.http_post(reverse('ruletransformation-list'),
                       {'ruleset': self.ruleset.pk, 'rule': self.rule.pk,
                           'transfo_type': Transformation.ACTION.value,
                           'transfo_value': Transformation.A_BYPASS.value},
                       status=status.HTTP_201_CREATED)
        self.assertEqual(self.ruleset.pk in content, True)
        params = '?transfo_type=%s&transfo_value=%s' % (Transformation.ACTION.value, Transformation.A_BYPASS.value)
        content = self.http_get(reverse('rule-transformation') + params)

        self.assertEqual(self.ruleset.pk in content, True)
        self.assertEqual(content[self.ruleset.pk]['rules'][0], self.rule.pk)
        self.assertEqual(content[self.ruleset.pk]['transformation']['transfo_key'], Transformation.ACTION.value)
        self.assertEqual(content[self.ruleset.pk]['transformation']['transfo_value'], Transformation.A_BYPASS.value)


class RestAPIRuleProcessingFilterTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)
        self.list_url = reverse('ruleprocessingfilter-list')
        self.detail_url = lambda x: reverse('ruleprocessingfilter-detail', args=(x,))
        self.ruleset = Ruleset.objects.create(name='test ruleset', descr='descr', created_date=timezone.now(), updated_date=timezone.now())

        self.DEFAULT_FILTER = {
            'filter_defs': [{
                'key': 'event_type',
                'value': 'http',
                'operator': 'equal'
            }],
            'action': 'suppress',
            'index': 0,
            'rulesets': [self.ruleset.pk]
        }
        self.DEFAULT_FILTER2 = {
            'filter_defs': [{
                'key': 'host',
                'value': 'probe-test',
                'operator': 'equal'
            }],
            'action': 'suppress',
            'index': 0,
            'rulesets': [self.ruleset.pk]
        }

        import scirius.utils
        self.middleware = scirius.utils.get_middleware_module

    def tearDown(self):
        import scirius.utils
        scirius.utils.get_middleware_module = self.middleware

    def _force_suricata_middleware(self):
        import scirius.utils
        scirius.utils.get_middleware_module = lambda x: import_module('suricata.%s' % x)

    def test_001_create(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f['comment'] = 'test comment'
        r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
        self.assertDictContainsSubset(self.DEFAULT_FILTER, r)
        self.filter_pk = r['pk']
        ua = UserAction.objects.last()
        self.assertEqual(ua.action_type, 'create_rule_filter')
        self.assertEqual(ua.comment, 'test comment')

    def test_002_create_invalid_filter(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f['filter_defs'] = []
        r = self.http_post(self.list_url, f, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {'filter_defs': ['This field is required.']})
        self.assertEqual(RuleProcessingFilter.objects.count(), 0)
        self.assertEqual(RuleProcessingFilterDef.objects.count(), 0)

        f = deepcopy(self.DEFAULT_FILTER)
        f['filter_defs'] = [{'key': 'test', 'operator': 'equal'}]
        r = self.http_post(self.list_url, f, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {'filter_defs': [{'value': ['This field is required.']}]})
        self.assertEqual(RuleProcessingFilter.objects.count(), 0)
        self.assertEqual(RuleProcessingFilterDef.objects.count(), 0)

    def test_003_update_filter_existing(self):
        self.test_001_create()

        r = self.http_patch(self.detail_url(self.filter_pk), {
            'filter_defs': [{'key': 'event_type', 'value': 'dns', 'operator': 'equal'}],
            'comment': 'test comment'
        })

        f = deepcopy(self.DEFAULT_FILTER)
        f['filter_defs'][0]['value'] = 'dns'
        self.assertDictContainsSubset(f, r)

        ua = UserAction.objects.last()
        self.assertEqual(ua.action_type, 'edit_rule_filter')
        self.assertEqual(ua.comment, 'test comment')

    def test_004_update_filter_add(self):
        self.test_001_create()

        # Filter value update
        new_filter = {
            'key': 'host',
            'value': 'probe1',
            'operator': 'equal'
        }
        filters = deepcopy(self.DEFAULT_FILTER['filter_defs'])
        filters.append(new_filter)

        r = self.http_patch(self.detail_url(self.filter_pk), {
            'filter_defs': filters
        })

        f = deepcopy(self.DEFAULT_FILTER)
        f['filter_defs'].append(new_filter)
        self.assertDictContainsSubset(f, r)
        self.assertEqual(len(r['filter_defs']), 2)

    def test_005_update_filter_rm(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f['filter_defs'].append({
            'key': 'host',
            'value': 'probe1',
            'operator': 'equal'
        })

        r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
        self.assertDictContainsSubset(f, r)

        r = self.http_patch(self.detail_url(r['pk']), {
            'filter_defs': self.DEFAULT_FILTER['filter_defs']
        })

        self.assertDictContainsSubset(self.DEFAULT_FILTER, r)
        self.assertEqual(len(r['filter_defs']), 1)

    def test_006_order_create_empty(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f.pop('index')

        r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
        self.assertDictContainsSubset(self.DEFAULT_FILTER, r)

    def test_007_order_create_append(self):
        self.test_001_create()

        f = deepcopy(self.DEFAULT_FILTER2)
        f.pop('index')

        r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
        f = deepcopy(self.DEFAULT_FILTER2)
        f['index'] = 1

        self.assertDictContainsSubset(f, r)

        r = self.http_get(self.list_url)
        self.assertDictContainsSubset(self.DEFAULT_FILTER, r['results'][0])
        self.assertDictContainsSubset(f, r['results'][1])

    def test_008_order_create_insert(self):
        self.test_001_create()

        self.http_post(self.list_url, self.DEFAULT_FILTER2, status=status.HTTP_201_CREATED)

        f1 = deepcopy(self.DEFAULT_FILTER)
        f1['index'] = 1

        r = self.http_get(self.list_url)
        self.assertDictContainsSubset(self.DEFAULT_FILTER2, r['results'][0])
        self.assertDictContainsSubset(f1, r['results'][1])

    def test_009_order_create_oob(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f['index'] = 1
        r = self.http_post(self.list_url, f, status=status.HTTP_400_BAD_REQUEST)

        self.assertDictEqual(r, {'index': ['Invalid index value (too high).']})

    def _check_order(self, expected):
        r = self.http_get(self.list_url)
        order = [f['pk'] for f in r['results']]
        self.assertListEqual(expected, order)
        indices = [f['index'] for f in r['results']]
        self.assertListEqual(indices, range(4))

    def _test_010_order_update(self, prev_index, new_index):
        filters = []
        for i in range(4):
            f = deepcopy(self.DEFAULT_FILTER)
            f.pop('index')
            r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
            filters.append(r['pk'])

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

        self.http_patch(self.detail_url(pk_to_move), {'index': new_index})
        self._check_order(expected)

    def test_011_order_update_oob(self):
        self.test_001_create()
        r = self.http_patch(self.detail_url(self.filter_pk), {'index': 2}, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {'index': ['Invalid index value (too high).']})

    def test_012_delete(self):
        self.test_007_order_create_append()

        self.http_delete(self.detail_url(self.filter_pk), {'comment': 'test comment'}, status=status.HTTP_204_NO_CONTENT)
        r = self.http_get(self.list_url)

        self.assertEqual(r['count'], 1)
        self.assertDictContainsSubset(self.DEFAULT_FILTER2, r['results'][0])

        ua = UserAction.objects.last()
        self.assertEqual(ua.action_type, 'delete_rule_filter')
        self.assertEqual(ua.comment, 'test comment')

    def test_013_suppress_validation_error(self):
        f = deepcopy(self.DEFAULT_FILTER)
        f['options'] = {'test': 'test'}
        r = self.http_post(self.list_url, f, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {'options': ['Action "suppress" does not accept options.']})

    def test_014_threshold_create(self):
        f = {
            'filter_defs': [{'key': 'alert.sid', 'value': '1', 'operator': 'equal'}],
            'action': 'threshold',
            'options': {'type': 'both', 'count': 2, 'seconds': 30, 'track': 'by_src'},
            'rulesets': [self.ruleset.pk]
        }
        r = self.http_post(self.list_url, f, status=status.HTTP_201_CREATED)
        self.assertDictContainsSubset(f, r)
        self.filter_pk = r['pk']

    def test_015_threshold_create_invalid(self):
        r = self.http_post(self.list_url, {
            'filter_defs': [{'key': 'alert.sid', 'value': '1', 'operator': 'equal'}],
            'action': 'threshold',
            'options': {'count': 2, 'seconds': 30, 'track': 'by_src'},
            'rulesets': [self.ruleset.pk]
        }, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {'options': [{'type': ['This field is required.']}]})

    def test_016_threshold_update(self):
        self.test_014_threshold_create()
        self.http_patch(self.detail_url(self.filter_pk), {
            'action': 'suppress',
            'options': {}
        })

    def test_017_threshold_update_invalid(self):
        self.test_014_threshold_create()
        r = self.http_patch(self.detail_url(self.filter_pk), {
            'action': 'threshold',
            'options': {}
        }, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {'options': [{'type': ['This field is required.'],
            'track': ['This field is required.']}]})

    def test_018_suri_tag_create_invalid(self):
        self._force_suricata_middleware()
        r = self.http_post(self.list_url, {
            'filter_defs': [{'key': 'src_ip', 'value': '192.168.0.1', 'operator': 'equal'}],
            'action': 'tag',
            'options': {'tag': 'test'},
            'rulesets': [self.ruleset.pk]
        }, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {'non_field_errors': ['Action "tag" is not supported.']})

    def test_019_suri_filter_defs_invalid(self):
        self._force_suricata_middleware()
        r = self.http_post(self.list_url, {
            'filter_defs': [{'key': 'src_ip', 'value': '192.168.0.1', 'operator': 'equal'}],
            'action': 'suppress',
            'rulesets': [self.ruleset.pk]
        }, status=status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(r, {'filter_defs': ['A filter with a key "alert.signature_id" is required.']})

    def test_020_suri_suppress_generate(self):
        self.http_post(self.list_url, {
            'filter_defs': [{'key': 'src_ip', 'value': '192.168.0.1', 'operator': 'equal'},
                {'key': 'alert.signature_id', 'value': '1', 'operator': 'equal'}],
            'action': 'suppress',
            'rulesets': [self.ruleset.pk]
        }, status=status.HTTP_201_CREATED)

        f = RuleProcessingFilter.objects.all()[0]
        suppress = f.get_threshold_content()
        self.assertEqual(suppress, 'suppress gen_id 1, sid_id 1, track by_src, ip 192.168.0.1\n')

    def test_021_suri_threshold_generate(self):
        self.http_post(self.list_url, {
            'filter_defs': [{'key': 'dest_ip', 'value': '192.168.0.1', 'operator': 'equal'},
                {'key': 'alert.signature_id', 'value': '1', 'operator': 'equal'}],
            'action': 'threshold',
            'options': {'type': 'both', 'track': 'by_dst'},
            'rulesets': [self.ruleset.pk]
        }, status=status.HTTP_201_CREATED)

        f = RuleProcessingFilter.objects.all()[0]
        threshold = f.get_threshold_content()
        self.assertEqual(threshold, 'threshold gen_id 1, sig_id 1, type both, track by_dst, count 1, seconds 60\n')


def order_update_lambda(a, b):
    return lambda x: RestAPIRuleProcessingFilterTestCase._test_010_order_update(x, a, b)


for a, b in itertools.product(range(4), range(5) + [None]):
    setattr(RestAPIRuleProcessingFilterTestCase, 'test_010_order_update_%i_to_%s' % (a, repr(b)), order_update_lambda(a, b))


class RestAPIListTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)
        self.router = router

    def test_001_default_order(self):
        # Ordering must be set to prevent:
        # /usr/share/python/scirius-pro/local/lib/python2.7/site-packages/rest_framework/pagination.py:208: UnorderedObjectListWarning: Pagination may yield inconsistent results with an unordered object_list: <class 'rules.models.RuleTransformation'> QuerySet
        for url, viewset, view_name in self.router.registry:
            if viewset().get_queryset().ordered or not issubclass(viewset, mixins.ListModelMixin):
                continue
            ERR = 'Viewset "%s" must set an "ordering" attribute or have an ordered queryset' % viewset.__name__
            self.assertTrue(hasattr(viewset, 'ordering'), ERR)
            self.assertNotEqual(len(viewset.ordering), 0, ERR)

    def test_002_list(self):
        for url, viewset, view_name in self.router.registry:
            if issubclass(viewset, mixins.ListModelMixin):
                self.http_get(reverse(view_name + '-list'))

    def test_003_list_order(self):
        for url, viewset, view_name in self.router.registry:
            if not hasattr(viewset, 'ordering_fields'):
                continue
            for field in viewset.ordering_fields:
                self.http_get(reverse(view_name + '-list') + '?ordering=%s' % field)

    def test_004_list_filter(self):
        for url, viewset, view_name in self.router.registry:
            if not hasattr(viewset, 'filter_fields'):
                continue
            for field in viewset.filter_fields:
                self.http_get(reverse(view_name + '-list') + '?%s=0' % field)

    def test_005_list_search(self):
        for url, viewset, view_name in self.router.registry:
            if not hasattr(viewset, 'search_fields'):
                continue
            url = reverse(view_name + '-list') + '?search=0'
            self.http_get(url)

    def test_006_options(self):
        for url, viewset, view_name in self.router.registry:
            if issubclass(viewset, mixins.ListModelMixin):
                self.http_options(reverse(view_name + '-list'))

    def test_007_documentation(self):
        for url, viewset, view_name in self.router.registry:
            self.assertNotEqual(viewset.__doc__, None, 'Viewset %s has no documentation' % view_name)


class RestAPIChangelogTestCase(RestAPITestBase, APITestCase):
    def _create_public_source(self):
        self.ruleset = Ruleset.objects.create(name='test ruleset', descr='descr', created_date=timezone.now(), updated_date=timezone.now())
        self.ruleset.save()

        params = {
                'name': 'sonic test public source',
                'comment': 'MyPublicComment',
                'public_source': 'oisf/trafficid',
                }
        self.http_post(reverse('publicsource-list'), params, status=status.HTTP_201_CREATED)
        sources = Source.objects.filter(name='sonic test public source')
        self.assertEqual(len(sources) == 1, True)

        sources_at_version = SourceAtVersion.objects.filter(source=sources[0])
        self.assertEqual(len(sources_at_version) == 1, True)

        self.assertEqual(sources_at_version[0].source == sources[0], True)

        self.public_source = sources[0]
        self.ruleset.sources.add(sources_at_version[0])

    def test_001_all_changelog(self):
        self._create_public_source()
        data = {"deleted": [], "updated": [{"msg": "SURICATA TRAFFIC-ID: Debian APT-GET", "category": "Suricata Traffic ID ruleset Sigs", "pk": 300000032, "sid": 300000032},
                {"msg": "SURICATA TRAFFIC-ID: Ubuntu APT-GET", "category": "Suricata Traffic ID ruleset Sigs", "pk": 300000033, "sid": 300000033}], "added": []}
        sha = '9b73cdc0e25b36ce3a80fdcced631f3769a4f6f6'

        SourceUpdate.objects.create(
            source=self.public_source,
            created_date=timezone.now(),
            data=json.dumps(data),
            version=sha,
            changed=len(data["deleted"]) + len(data["added"]) + len(data["updated"]),
        )

        self.public_source.update()
        response = self.http_get(reverse('sourceupdate-list'))
        self.assertEqual(response['results'][0]['source'], self.public_source.pk)
        self.assertEqual(response['results'][0]['data']['updated'], data['updated'])


class RestAPISystemSettingsTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.system_settings = SystemSettings.objects.get_or_create(id=1)[0]

    def test_001_system_get(self):
        content = self.http_get(reverse('systemsettings'))
        self.assertEqual('custom_elasticsearch' in content, True)
        self.assertEqual('elasticsearch_url' in content, True)
        self.assertEqual('http_proxy' in content, True)
        self.assertEqual('use_http_proxy' in content, True)
        self.assertEqual('use_elasticsearch' in content, True)

    def test_002_system_settings_update(self):
        params = {'use_http_proxy': True, 'http_proxy': '', 'https_proxy': '', 'use_elasticsearch': True, 'custom_elasticsearch': False, 'elasticsearch_url': 'http://elasticsearch:9200/'}
        content = self.http_patch(reverse('systemsettings'), params)
        self.assertEqual(content['use_http_proxy'], True)
        self.assertEqual(content['use_elasticsearch'], True)

        params = {'use_http_proxy': False, 'http_proxy': '', 'https_proxy': '', 'use_elasticsearch': False, 'custom_elasticsearch': False, 'elasticsearch_url': 'http://elasticsearch:9200/'}
        content = self.http_put(reverse('systemsettings'), params)
        self.assertEqual(content['use_http_proxy'], False)
        self.assertEqual(content['use_elasticsearch'], False)
