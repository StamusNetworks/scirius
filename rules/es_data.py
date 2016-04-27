'''
Copyright(C) 2016, Stamus Networks
Written by Laurent Defert <lds@stamus-networks.com>

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
'''

import json
import os
import tarfile
import tempfile
from cStringIO import StringIO
from shutil import rmtree
from time import strftime

from django.conf import settings
from elasticsearch import Elasticsearch


class ESData(object):
    def __init__(self):
        es_addr = 'http://%s/' % settings.ELASTICSEARCH_ADDRESS
        self.client = Elasticsearch([es_addr])

    def _kibana_remove(self, _type, body):
        i = 0
        ids = []

        while True:
            res = self.client.search(index='.kibana', from_=i, doc_type=_type, body=body, request_cache=False)
            if len(res['hits']['hits']) == 0:
                break
            i += 10

            _ids = [hit['_id'] for hit in res['hits']['hits']]
            ids += _ids

        for _id in ids:
            self.client.delete(index='.kibana', doc_type=_type, id=_id, refresh=True)


    def _kibana_export_obj(self, dest, _type, body):
        i = 0

        dest = os.path.join(dest, _type)
        os.makedirs(dest)

        while True:
            res = self.client.search(index='.kibana', from_=i, doc_type=_type, body=body)
            if len(res['hits']['hits']) == 0:
                break
            i += 10

            for hit in res['hits']['hits']:
                _id = hit['_id']
                filename = os.path.join(dest, _id)
                filename += '.json'
                res = self.client.get(index='.kibana', doc_type=_type, id=_id)
                with open(filename, 'w') as f:
                    f.write(json.dumps(res['_source'], separators= (',', ':')))

    def kibana_export(self, full=False):
        dest = tempfile.mkdtemp()
        _types = ('search', 'visualization', 'dashboard')

        if full:
            _types = _types + ('index-pattern',)
            body = {'query': {'match_all': {}}}
        else:
            body = {
                'query': {
                    'query_string': {
                        'query': 'NOT title: SN *'
                    }
                }
            }

        for _type in _types:
            self._kibana_export_obj(dest, _type, body)

        f = tempfile.NamedTemporaryFile(delete=False)
        tar_name = 'scirius-dashboards-%s' % strftime('%Y%m%d%H%M')
        tar = tarfile.open(mode='w:bz2', fileobj=f)
        tar.add(dest, tar_name)
        tar.close()
        rmtree(dest)
        f.close()
        tar_name += '.tar.bz2'
        return tar_name, f.name

    def _kibana_inject(self, _type, _file):
        with open(_file) as f:
            content = f.read()
        name = _file.rsplit('/', 1)[1]
        name = name.rsplit('.', 1)[0]
        self.client.create(index='.kibana', doc_type=_type, id=name, body=content, refresh=True)

    def _kibana_set_default_index(self, idx):
        res = self.client.search(index='.kibana', doc_type='config', body={'query': {'match_all': {}}}, request_cache=False)
        for hit in res['hits']['hits']:
            content = hit['_source']
            content['defaultIndex'] = idx
            self.client.update(index='.kibana', doc_type='config', id=hit['_id'], body={'doc': content}, refresh=True)

    def _get_kibana_files(self, source, _type):
        files = []
        path = os.path.join(source, _type)
        if not os.path.isdir(path):
            return []
        for _file in os.listdir(path):
            if not _file.endswith('.json'):
                continue
            _file = os.path.join(path, _file)
            files.append(_file)
        return files

    def _get_kibana_subdirfiles(self, _type):
        files = []
        for _dir in os.listdir(settings.KIBANA_DASHBOARDS_PATH):
            src_path = os.path.join(settings.KIBANA_DASHBOARDS_PATH, _dir)
            if os.path.isdir(src_path):
                files += self._get_kibana_files(src_path, _type)
        return files

    def kibana_import_fileobj(self, fileobj):
        tar = tarfile.open(mode='r:bz2', fileobj=fileobj)
        tmpdir = tempfile.mkdtemp()
        tar.extractall(tmpdir)
        tar.close()

        subdirs = os.listdir(tmpdir)
        if len(subdirs) != 1:
            raise Exception('Archive does not appear to contain dashboards')
        source = os.path.join(tmpdir, subdirs[0])
        if self._get_kibana_files(source, 'dashboard') == []:
            raise Exception('Archive does not appear to contain dashboards')

        for _type in ('search', 'visualization', 'dashboard'):
            for _file in self._get_kibana_files(source, _type):
                self._kibana_inject(_type, _file)
        count = len(self._get_kibana_files(source, 'dashboard'))
        rmtree(tmpdir)
        return count

    def kibana_clear(self):
        body = {
            'query': {
                'query_string': {
                    'query': 'NOT title: SN *'
                }
            }
        }

        _types = ('search', 'visualization', 'dashboard')
        for _type in _types:
            self._kibana_remove(_type, body)

    def kibana_reset(self):
        if not os.path.isdir(settings.KIBANA_DASHBOARDS_PATH):
            raise Exception('Please make sure Kibana dashboards are installed at %s' % settings.KIBANA_DASHBOARDS_PATH)

        if self._get_kibana_subdirfiles('index-pattern') == []:
            raise Exception('Please make sure Kibana dashboards are installed at %s: no index-pattern found' % settings.KIBANA_DASHBOARDS_PATH)

        self._kibana_remove('dashboard', {'query': {'match': {'title': 'SN *'}}})
        self._kibana_remove('visualization', {'query': {'match': {'title': 'SN *'}}})
        self._kibana_remove('search', {'query': {'match': {'title': 'SN *'}}})
        self._kibana_remove('index-pattern', {'query': {'match_all': {}}})

        for _type in ('index-pattern', 'search', 'visualization', 'dashboard'):
            for _file in self._get_kibana_subdirfiles(_type):
                self._kibana_inject(_type, _file)

        self._kibana_set_default_index(u'logstash-*')
