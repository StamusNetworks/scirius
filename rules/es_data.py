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

from __future__ import unicode_literals
import logging
import json
import os
import sys
import tarfile
import tempfile
from cStringIO import StringIO
from shutil import rmtree
from time import strftime, sleep

import urllib2

from django.conf import settings
from elasticsearch import Elasticsearch, ConnectionError

from rules.models import get_es_address
from rules.es_graphs import get_es_major_version

# Avoid logging every request
es_logger = logging.getLogger('elasticsearch')
es_logger.setLevel(logging.INFO)

# Mapping
def get_kibana_mappings():
    if get_es_major_version() < 6:
        return { "dashboard":
            { "properties":
                {
                  "title": { "type": "string" },
                  "hits": { "type": "integer" },
                  "description": { "type": "string" },
                  "panelsJSON": { "type": "string" },
                  "optionsJSON": { "type": "string" },
                  "uiStateJSON": { "type": "string" },
                  "version": { "type": "integer" },
                  "timeRestore": { "type": "boolean" },
                  "timeTo": { "type": "string" },
                  "timeFrom": { "type": "string" },
                }
            } , "search" : { "properties" :
                {
                    "title": { "type": "string" },
                    "description": { "type": "string" },
                    "hits": { "type": "integer" },
                    "columns": { "type": "string" },
                    "sort": { "type": "string" },
                    "version": { "type": "integer" }
                }
            }, "visualization": { "properties":
                {
                    "title": { "type": "string" },
                    "uiStateJSON": { "type": "string" },
                    "description": { "type": "string" },
                    "savedSearchId": { "type": "string" },
                    "version": { "type": "integer" }
                }
            }
        }
    else:
        return {
            "doc" : {
                "properties" : {
                    "config" : {
                        "properties" : {
                            "buildNum" : {
                                "type" : "keyword"
                            },
                            "defaultIndex" : {
                                "type" : "text",
                                "fields" : {
                                    "keyword" : {
                                        "type" : "keyword",
                                        "ignore_above" : 256
                                    }
                                }
                            },
                            "telemetry:optIn" : {
                                "type" : "boolean"
                            }
                        }
                    },
                    "dashboard" : {
                        "properties" : {
                            "description" : {
                                "type" : "text"
                            },
                            "hits" : {
                                "type" : "integer"
                            },
                            "kibanaSavedObjectMeta" : {
                                "properties" : {
                                    "searchSourceJSON" : {
                                        "type" : "text"
                                    }
                                }
                            },
                            "optionsJSON" : {
                                "type" : "text"
                            },
                            "panelsJSON" : {
                                "type" : "text"
                            },
                            "refreshInterval" : {
                                "properties" : {
                                    "display" : {
                                        "type" : "keyword"
                                    },
                                    "pause" : {
                                        "type" : "boolean"
                                    },
                                    "section" : {
                                        "type" : "integer"
                                    },
                                    "value" : {
                                        "type" : "integer"
                                    }
                                }
                            },
                            "timeFrom" : {
                                "type" : "keyword"
                            },
                            "timeRestore" : {
                                "type" : "boolean"
                            },
                            "timeTo" : {
                                "type" : "keyword"
                            },
                            "title" : {
                                "type" : "text"
                            },
                            "uiStateJSON" : {
                                "type" : "text"
                            },
                            "version" : {
                                "type" : "integer"
                            }
                        }
                    },
                    "graph-workspace" : {
                        "properties" : {
                            "description" : {
                                "type" : "text"
                            },
                            "kibanaSavedObjectMeta" : {
                                "properties" : {
                                    "searchSourceJSON" : {
                                        "type" : "text"
                                    }
                                }
                            },
                            "numLinks" : {
                                "type" : "integer"
                            },
                            "numVertices" : {
                                "type" : "integer"
                            },
                            "title" : {
                                "type" : "text"
                            },
                            "version" : {
                                "type" : "integer"
                            },
                            "wsState" : {
                                "type" : "text"
                            }
                        }
                    },
                    "index-pattern" : {
                        "properties" : {
                            "fieldFormatMap" : {
                                "type" : "text"
                            },
                            "fields" : {
                                "type" : "text"
                            },
                            "intervalName" : {
                                "type" : "keyword"
                            },
                            "notExpandable" : {
                                "type" : "boolean"
                            },
                            "sourceFilters" : {
                                "type" : "text"
                            },
                            "timeFieldName" : {
                                "type" : "keyword"
                            },
                            "title" : {
                                "type" : "text"
                            }
                        }
                    },
                    "search" : {
                        "properties" : {
                            "columns" : {
                                "type" : "keyword"
                            },
                            "description" : {
                                "type" : "text"
                            },
                            "hits" : {
                                "type" : "integer"
                            },
                            "kibanaSavedObjectMeta" : {
                                "properties" : {
                                    "searchSourceJSON" : {
                                        "type" : "text"
                                    }
                                }
                            },
                            "sort" : {
                                "type" : "keyword"
                            },
                            "title" : {
                                "type" : "text"
                            },
                            "version" : {
                                "type" : "integer"
                            }
                        }
                    },
                    "server" : {
                        "properties" : {
                            "uuid" : {
                                "type" : "keyword"
                            }
                        }
                    },
                    "timelion-sheet" : {
                        "properties" : {
                            "description" : {
                                "type" : "text"
                            },
                            "hits" : {
                                "type" : "integer"
                            },
                            "kibanaSavedObjectMeta" : {
                                "properties" : {
                                    "searchSourceJSON" : {
                                        "type" : "text"
                                    }
                                }
                            },
                            "timelion_chart_height" : {
                                "type" : "integer"
                            },
                            "timelion_columns" : {
                                "type" : "integer"
                            },
                            "timelion_interval" : {
                                "type" : "keyword"
                            },
                            "timelion_other_interval" : {
                                "type" : "keyword"
                            },
                            "timelion_rows" : {
                                "type" : "integer"
                            },
                            "timelion_sheet" : {
                                "type" : "text"
                            },
                            "title" : {
                                "type" : "text"
                            },
                            "version" : {
                                "type" : "integer"
                            }
                        }
                    },
                    "type" : {
                        "type" : "keyword"
                    },
                    "updated_at" : {
                        "type" : "date"
                    },
                    "url" : {
                        "properties" : {
                            "accessCount" : {
                                "type" : "long"
                            },
                            "accessDate" : {
                                "type" : "date"
                            },
                            "createDate" : {
                                "type" : "date"
                            },
                            "url" : {
                                "type" : "text",
                                "fields" : {
                                    "keyword" : {
                                        "type" : "keyword",
                                        "ignore_above" : 2048
                                    }
                                }
                            }
                        }
                    },
                    "visualization" : {
                        "properties" : {
                            "description" : {
                                "type" : "text"
                            },
                            "kibanaSavedObjectMeta" : {
                                "properties" : {
                                    "searchSourceJSON" : {
                                        "type" : "text"
                                    }
                                }
                            },
                            "savedSearchId" : {
                                "type" : "keyword"
                            },
                            "title" : {
                                "type" : "text"
                            },
                            "uiStateJSON" : {
                                "type" : "text"
                            },
                            "version" : {
                                "type" : "integer"
                            },
                            "visState" : {
                                "type" : "text"
                            }
                        }
                    }
                }
            }
        }

KIBANA6_NAMESPACE = {
    "id": "default",
    "name": "Default",
    "description": "This is your default space!",
    "color": "#00bfb3",
}

class ESData(object):
    def __init__(self):
        es_addr = get_es_address()
        self.client = Elasticsearch([es_addr])

    def _kibana_request(self, url, data):
        headers = {
            'content-type': 'application/json',
            'kbn-xsrf': True
        }
        data = json.dumps(data)
        kibana_url = settings.KIBANA_URL + url
        req = urllib2.Request(kibana_url, data, headers=headers)
        urllib2.urlopen(req)
        return req

    def _kibana_remove(self, _type, body):
        i = 0
        ids = []

        if get_es_major_version() >= 6:
            body['query']['query_string']['query'] += ' type:%s' % _type
            _type = 'doc'

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
            if get_es_major_version() < 6:
                res = self.client.search(index='.kibana', from_=i, doc_type=_type, body=body)
            else:
                res = self.client.search(index='.kibana', from_=i, body=body)

            if len(res['hits']['hits']) == 0:
                break
            i += 10

            for hit in res['hits']['hits']:

                _id = hit['_id']
                filename = os.path.join(dest, _id)
                filename += '.json'

                if get_es_major_version() < 6:
                    res = self.client.get(index='.kibana', doc_type=_type, id=_id)
                else:
                    res = self.client.get(index='.kibana', doc_type='doc', id=_id)

                with open(filename, 'w') as f:
                    f.write(json.dumps(res['_source'], separators= (',', ':')))

    def kibana_export(self, full=False):
        dest = tempfile.mkdtemp()
        _types = ('search', 'visualization', 'dashboard')

        if full:
            _types = _types + ('index-pattern',)

        for _type in _types:
            if get_es_major_version() < 6:
                if full:
                    body = {'query': {'match_all': {}}}
                else:
                    body = {
                        'query': {
                            'query_string': {
                                'query': 'NOT title: SN *'
                            }
                        }
                    }
            else:
                if full:
                    body = {
                        'query': {
                            'query_string': {
                                'query': 'type: %s' % _type
                            }
                        }
                    }
                else:
                    body = {
                        'query': {
                            'query_string': {
                                'query': 'type: %s AND NOT title: SN *' % _type
                            }
                        }
                    }
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

    def _create_kibana_mappings(self):
        if not self.client.indices.exists('.kibana'):
            self.client.indices.create(index='.kibana',body={ "mappings": get_kibana_mappings() })
            self.client.indices.refresh(index='.kibana')
        elif not "visualization" in unicode(self.client.indices.get_mapping(index='.kibana')):
            self.client.indices.delete(index='.kibana')
            self.client.indices.create(index='.kibana',body={ "mappings": get_kibana_mappings() })
            self.client.indices.refresh(index='.kibana')

    def _kibana_inject(self, _type, _file):
        with open(_file) as f:
            content = f.read()
        name = _file.rsplit('/', 1)[1]
        name = name.rsplit('.', 1)[0]
        if get_es_major_version() < 6:
            doc_type = _type
        else:
            doc_type = 'doc'
        self.client.create(index='.kibana', doc_type=doc_type, id=name, body=content, refresh=True)

    def _kibana_set_default_index(self, idx):
        if get_es_major_version() < 6:
            res = self.client.search(index='.kibana', doc_type='config', body={'query': {'match_all': {}}}, request_cache=False)
        else:
            body = {'query': {'query_string': {'query': 'type: config'}}}
            res = self.client.search(index='.kibana', doc_type='doc', body=body, request_cache=False)

        for hit in res['hits']['hits']:
            content = hit['_source']
            content['defaultIndex'] = idx

            if get_es_major_version() < 6:
                self.client.update(index='.kibana', doc_type='config', id=hit['_id'], body={'doc': content}, refresh=True)
            else:
                self.client.update(index='.kibana', doc_type='doc', id=hit['_id'], body=content, refresh=True)
        else:
            if get_es_major_version() >= 6:
                self._kibana_request('/api/kibana/settings/defaultIndex', {'value': 'logstash-*'})
            else:
                print >> sys.stderr, "Warning: unknown ES version, not setting Kibana's defaultIndex"

    def _get_dashboard_dir(self):
        if get_es_major_version() < 6 or not hasattr(settings, 'KIBANA6_DASHBOARDS_PATH'):
            # Use KIBANA_DASHBOARDS_PATH when using ES<6 or when KIBANA6_DASHBOARDS_PATH is not set
            return settings.KIBANA_DASHBOARDS_PATH
        return settings.KIBANA6_DASHBOARDS_PATH

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
        for _dir in os.listdir(self._get_dashboard_dir()):
            src_path = os.path.join(self._get_dashboard_dir(), _dir)
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
            raise Exception('Archive does not appear to contain dashboards, visualizations or searches')
        source = os.path.join(tmpdir, subdirs[0])

        self._create_kibana_mappings()

        count = 0
        for _type in ('search', 'visualization', 'dashboard'):
            source_files = self._get_kibana_files(source, _type)
            count += len(source_files)
            for _file in source_files:
                self._kibana_inject(_type, _file)
        rmtree(tmpdir)

        if count == 0:
            raise Exception('No data loaded')

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
        self._create_kibana_mappings()

        if not os.path.isdir(self._get_dashboard_dir()):
            raise Exception('Please make sure Kibana dashboards are installed at %s' % self._get_dashboard_dir())

        if self._get_kibana_subdirfiles('index-pattern') == []:
            raise Exception('Please make sure Kibana dashboards are installed at %s: no index-pattern found' % self._get_dashboard_dir())

        self._kibana_remove('dashboard', {'query': {'query_string': {'query': 'SN*'}}})
        self._kibana_remove('visualization', {'query': {'query_string': {'query': 'SN*'}}})
        self._kibana_remove('search', {'query': {'query_string': {'query': 'SN*'}}})
        self._kibana_remove('index-pattern', {'query': {'query_string': {'query': '*'}}})

        for _type in ('index-pattern', 'search', 'visualization', 'dashboard'):
            for _file in self._get_kibana_subdirfiles(_type):
                self._kibana_inject(_type, _file)

        if get_es_major_version() >= 6:
            self._kibana_request('/api/spaces/space', KIBANA6_NAMESPACE)

        self._kibana_set_default_index('logstash-*')

    def _get_indexes(self):
        res = self.client.indices.stats()
        indexes = res['indices'].keys()
        idxs = list(indexes)

        for idx in idxs:
            if idx.startswith('.kibana'):
                indexes.pop(indexes.index(idx))

        return indexes

    def es_clear(self):
        indexes = self._get_indexes()
        self.client.indices.delete(index=indexes)
        return len(indexes)

    def wait_until_up(self):
        for i in xrange(1024):
            try:
                ret = self.client.cluster.health(wait_for_status='green', request_timeout=15 * 60)
                if ret.get('status') == 'green':
                    break
                sleep(10)
            except ConnectionError:
                pass
