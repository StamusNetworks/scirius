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


    def _kibana_export(self, dest, _type, body):
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
