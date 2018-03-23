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

from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from models import Category, Rule, Ruleset, Source, SourceAtVersion, Transformation

import tempfile
from shutil import rmtree

class SourceCreationTestCase(TestCase):
    def setUp(self):
        self.tmpdirname = tempfile.mkdtemp()
        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            self.source = Source.objects.create(name="ET Open",
                                       method = "http",
                                       datatype = "sigs",
                                       uri="https://rules.emergingthreats.net/open/suricata-2.0.1/emerging.rules.tar.gz",
                                       created_date=timezone.now())

    def tearDown(self):
        rmtree(self.tmpdirname)

    def test_source_update(self):
        """Test source update"""
        self.source.update()
        self.assertEqual(len(SourceAtVersion.objects.filter(source = self.source)), 1)
        self.assertNotEqual(len(Category.objects.filter(source = self.source)), 0)


class RestAPITestBase(object):
    def setUp(self):
        self.user = User.objects.create(username='scirius', password='scirius', is_superuser=True, is_staff=True)
        self.client.force_login(self.user)

    def _make_request(self, method, url, *args, **kwargs):
        func = getattr(self.client, method)
        http_status = kwargs.pop('status', status.HTTP_200_OK)
        kwargs['format'] = 'json'
        response = func(url, *args, **kwargs)
        self.assertEqual(response.status_code, http_status, 'Request failed: \n%s %s\n%s %s\n%s' %
                (method.upper(), url, response.status_code, response.reason_phrase, response))
        return getattr(response, 'data', None)

    http_get = lambda self, *args, **kwargs: self._make_request('get', *args, **kwargs)
    http_post = lambda self, *args, **kwargs: self._make_request('post', *args, **kwargs)
    http_put = lambda self, *args, **kwargs: self._make_request('put', *args, **kwargs)
    http_patch = lambda self, *args, **kwargs: self._make_request('patch', *args, **kwargs)


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

        content = """alert ip $HOME_NET any -> [103.207.29.161,103.207.29.171,103.225.168.222,103.234.36.190,103.234.37.4,103.4.164.34,
        103.6.207.37,104.131.93.109,104.140.137.152,104.143.5.144,104.144.167.131,104.144.167.251,104.194.206.108,
        104.199.121.36,104.207.154.26,104.223.87.207,104.43.200.222,106.187.48.236,107.161.19.71] 
        any (msg:"ET CNC Shadowserver Reported CnC Server IP group 1"; 
        reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,www.shadowserver.org; 
        threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; 
        flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404000; rev:4933;)"""

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
        self.http_patch(reverse('ruletransformation-detail',  args=(self.rule.pk,)),
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
