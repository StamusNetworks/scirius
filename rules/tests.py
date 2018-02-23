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
        self.rule = Rule.objects.create(sid=1, category=self.category, msg='test rule',
                content='test rule')
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
