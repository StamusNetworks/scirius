

from datetime import datetime
from time import time
import logging
from collections import OrderedDict
from pprint import pformat
from traceback import format_exc
import os
import json

from elasticsearch import Elasticsearch, Transport, ElasticsearchException, TransportError, ConnectionError, ConnectionTimeout, RequestsHttpConnection
from django.conf import settings
from rest_framework.response import Response
from rest_framework.utils.urls import replace_query_param, remove_query_param

from rules.models import get_es_address, get_system_settings
from scirius.utils import get_middleware_module
from scirius.rest_utils import SciriusSetPagination


# ES requests timeout (keep this below Scirius's ajax requests timeout)
es_logger = logging.getLogger('elasticsearch')


def normalize_es_url(es_url):
    es_urls = []
    for url in es_url.split(','):
        if not url.endswith('/'):
            url = url + '/'
        es_urls.append(url)
    return ','.join(es_urls)


def get_ordering(request, default):
    ordering = request.query_params.get('ordering', default)

    if ordering[0] == '-':
        return True, ordering[1:]
    return False, ordering


class ESPaginator(SciriusSetPagination):
    def __init__(self, request):
        super(ESPaginator, self).__init__()
        self.request = request

    def _get_current_page(self):
        page = self.request.query_params.get(self.page_query_param, 1)
        return int(page)

    def get_es_params(self, view):
        reverse, order = get_ordering(self.request, 'ip')
        order_sort = 'desc' if reverse else 'asc'
        page_size = self.get_page_size(self.request)
        return {
            'size': page_size,
            'from': (self._get_current_page() - 1) * page_size,
            'sort_field': order,
            'sort_order': order_sort
        }

    def get_paginated_response(self, data, full=False):
        from rules.es_graphs import get_es_major_version
        total = data['hits']['total']
        if get_es_major_version() >= 7:
            total = total['value']

        return Response(OrderedDict([
            ('count', total),
            ('next', self.get_next_link(total)),
            ('previous', self.get_previous_link()),
            ('results', [entry['_source'] if not full else entry for entry in data['hits']['hits']])
        ]))

    def get_next_link(self, total):
        if self._get_current_page() * self.get_page_size(self.request) >= total:
            return None
        url = self.request.build_absolute_uri()
        page_number = self._get_current_page() + 1
        return replace_query_param(url, self.page_query_param, page_number)

    def get_previous_link(self):
        if self._get_current_page() <= 1:
            return None
        url = self.request.build_absolute_uri()
        page_number = self._get_current_page() - 1
        if page_number == 1:
            return remove_query_param(url, self.page_query_param)
        return replace_query_param(url, self.page_query_param, page_number)


class ESWrap(object):
    '''Wraps elasticsearch-py objects, and sub-objects, to log failures and ESError exceptions'''
    def __init__(self, _es):
        self._es = _es

    def __getattr__(self, attr):
        if attr == '_es':
            return self._es
        return ESWrap(getattr(self._es, attr))

    def __call__(self, *args, **kwargs):
        if settings.DEBUG:
            msg = ''
            body = kwargs.get('body')
            if 'index' in kwargs:
                msg = kwargs['index']
                if body:
                    msg += ':\n'
            if body:
                msg += pformat(body)

            if msg:
                es_logger.info(msg)

        try:
            return self._es(*args, **kwargs)
        except ElasticsearchException as e:
            from rules.es_graphs import ESError
            if isinstance(e, ConnectionTimeout):
                msg = 'ES connection timeout'
            elif isinstance(e, ConnectionError):
                msg = 'ES connection error: %s' % e.info
            elif isinstance(e, TransportError):
                msg = 'ES transport error: %s %s' % (e.status_code, e.error)
                if settings.DEBUG and getattr(e, 'info', None):
                    msg += '\n%s' % e.info
                else:
                    es_logger.error('%s %s %s' % (e.status_code, e.error, e.info))
            else:
                msg = 'ES error'

            es_logger.error(format_exc() + '\n' + msg)
            raise ESError('ES failure: %s' % msg, e)


class ESTransport(Transport):
    def __init__(self, es_addr, *args, **kwargs):
        if len(es_addr) == 1:
            # Prevent retry on connection timeout
            kwargs['max_retries'] = 0
        super().__init__(es_addr, *args, **kwargs)


class ESConnection(RequestsHttpConnection):
    '''
    https://github.com/elastic/elasticsearch-py/issues/275#issuecomment-218403073
    '''
    def __init__(self, *args, **kwargs):
        proxies = kwargs.pop('proxies', {})
        super().__init__(*args, **kwargs)
        self.session.proxies = proxies


class ESQuery:
    TIMEOUT = 30
    MAX_RESULT_WINDOW = 10000
    INTERVAL_POINTS = 100
    INDEX = settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX

    def __init__(self, request, es_address=None, from_date=None, to_date=None, interval=None, qfilter=None):
        self.from_date = from_date
        self.to_date = to_date
        self.interval = interval
        self.request = request
        self.qfilter = qfilter

        if es_address is None:
            es_address = get_es_address()
        es_address = es_address.split(',')

        es_params = {
            'hosts': es_address,
            'transport_class': ESTransport
        }

        if es_address[0].startswith('https'):
            ca_certs = None
            requests_ca_path = os.getenv('REQUESTS_CA_BUNDLE')
            if requests_ca_path:
                ca_certs = requests_ca_path

            es_params.update({
                'use_ssl': True,
                'verify_certs': True,
                'ca_certs': ca_certs
            })

        if get_system_settings().custom_elasticsearch and get_system_settings().use_proxy_for_es:
            es_params.update({
                'connection_class': ESConnection,
                'proxies': get_system_settings().get_proxy_params()
            })

        es = Elasticsearch(**es_params)
        self.es = ESWrap(es)

    def _from_date(self):
        if self.from_date:
            return self.from_date
        elif self.request and ('from_date' in self.request.GET or 'start_date' in self.request.GET):
            if 'from_date' in self.request.GET:
                key = 'from_date'
            elif 'start_date' in self.request.GET:
                key = 'start_date'
            from_date = int(self.request.GET[key])
        else:
            # 30 days ago
            from_date = (time() - (30 * 24 * 60 * 60)) * 1000

        if from_date >= self._to_date(es_format=False):
            # Asking for a date in the future (browser of the user has clock out of sync), return last hour
            from_date = self._to_date(es_format=False) - (60 * 60 * 1000)

        return int(from_date)

    def _to_date(self, es_format=True):
        if self.to_date:
            return self.to_date

        to_date = 'now'
        if self.request and ('to_date' in self.request.GET or 'end_date' in self.request.GET):
            if 'to_date' in self.request.GET:
                key = 'to_date'
            elif 'end_date' in self.request.GET:
                key = 'end_date'

            if self.request.GET[key] != 'now':
                to_date = int(self.request.GET[key])

        if to_date == 'now':
            if es_format:
                return 'now'
            else:
                to_date = time() * 1000
        return int(to_date)

    def _interval(self, dictionary=None):
        if self.interval:
            return self.interval
        if dictionary and 'interval' in dictionary:
            interval = int(dictionary['interval']) * 1000
        elif self.request and 'interval' in self.request.GET:
            interval = int(self.request['interval']) * 1000
        else:
            interval = int((self._to_date(es_format=False) - self._from_date()) / self.INTERVAL_POINTS)

        if interval < 1:
            return 1

        return interval

    def _es_interval(self):
        return '%sms' % self._interval()

    def _scroll_query(self, scroll_duration, *args, **kwargs):
        index = self._get_index()

        body = self._get_query(*args, **kwargs)
        if 'size' in body:
            raise Exception('size parameter cannot be used in scroll queries')
        data = self.es.search(body=body,
                              index=index,
                              ignore_unavailable=True,
                              _source=True,
                              request_timeout=self.TIMEOUT,
                              size=self.MAX_RESULT_WINDOW,
                              scroll=scroll_duration)

        scroll_id = data.get('_scroll_id')
        count = self._parse_total_hits(data) - self.MAX_RESULT_WINDOW
        yield data

        while count > 0:
            data = self.es.scroll(scroll_id=scroll_id, scroll=scroll_duration)
            yield data

            count -= self.MAX_RESULT_WINDOW

        if scroll_id:
            # Ignore 404 to prevent an exception when the query exceeded scroll_duration
            self.es.clear_scroll(scroll_id=scroll_id, ignore=[404])

    def _scroll_composite(self, index, body):
        if 'aggregations' not in body:
            raise Exception('Missing aggregation')
        if len(body['aggregations']) != 1:
            raise Exception('Unexpected aggregation count')
        if 'composite' not in list(body['aggregations'].values())[0]:
            raise Exception('Unexpected aggregation type')

        after = None

        # https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations-bucket-composite-aggregation.html#_after
        while True:
            if after:
                list(body['aggregations'].values())[0]['composite']['after'] = after

            list(body['aggregations'].values())[0]['composite']['size'] = 10000
            data = self.es.search(body=body,
                                  index=index,
                                  ignore_unavailable=True,
                                  request_timeout=self.TIMEOUT)

            yield data

            if 'aggregations' not in data:
                # No data matches the query
                break

            after = list(data['aggregations'].values())[0].get('after_key')

            if after is None:
                break

    def get_indexes(self):
        res = self.es.indices.stats()
        indexes = list(res['indices'].keys())
        idxs = list(indexes)

        for idx in idxs:
            if idx.startswith('.kibana'):
                indexes.pop(indexes.index(idx))

        return indexes

    def _es_interval_kw(self):
        from rules.es_graphs import get_es_major_version
        if get_es_major_version() < 7:
            return 'interval'
        return 'fixed_interval'

    def _es_bool_clauses(self):
        if self.request:
            return get_middleware_module('common').es_bool_clauses(self.request)
        return ''

    def _get_index_name(self):
        return self.INDEX

    def _get_index(self):
        index = self._get_index_name()
        if not index.endswith('-'):
            return index

        if settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'daily':
            dt = (24 * 60 * 60)
            fmt = '%Y.%m.%d'
        elif settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'hourly':
            dt = (60 * 60)
            fmt = '%Y.%m.%d.%H'
        else:
            raise Exception('Invalid ELASTICSEARCH_LOGSTASH_TIMESTAMPING setting value: %s' % settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING)

        end = (self._to_date(es_format=False) / 1000) + dt
        date = self._from_date() / 1000
        indexes = []
        while date <= end:
            d = datetime.fromtimestamp(date)
            indexes.append("%s%s*" % (index, d.strftime(fmt)))
            date += dt

        if len(indexes) > 20:
            return index + '2*'
        return ','.join(indexes)

    def _get_query(self, *args, **kwargs):
        raise NotImplementedError('_get_query method of ESQuery must be overriden')

    def _qfilter(self):
        if self.qfilter:
            return self.qfilter

        query_filter = get_middleware_module('common').es_query_string(self.request)
        if self.request and 'qfilter' in self.request.GET:
            query_filter += ' AND ' + self.request.GET['qfilter']
        return query_filter

    def _hosts(self):
        hosts = ['*']
        if self.request and 'hosts' in self.request.GET:
            hosts = self.request.GET['hosts'].split(',')

        if hosts == ['*']:
            # use _exists_ in case analyze_wildcard is false
            hosts_filter = '_exists_:%s' % settings.ELASTICSEARCH_HOSTNAME
        else:
            hosts_filter = ['%s:%s' % (settings.ELASTICSEARCH_HOSTNAME, h) for h in hosts]
            hosts_filter = '(%s)' % ' '.join(hosts_filter)

        return hosts_filter

    def _parse_total_hits(self, resp):
        from rules.es_graphs import get_es_major_version
        if get_es_major_version() < 7:
            return resp['hits']['total']
        return resp['hits']['total']['value']

    def get(self, *args, **kwargs):
        index = self._get_index()
        body = self._get_query(*args, **kwargs)
        return self.es.search(body=body,
                              index=index,
                              ignore_unavailable=True,
                              _source=True,
                              request_timeout=self.TIMEOUT)

    def is_read_only(self, index=None):
        settings_ = self.es.indices.get_settings(index)

        for val in settings_.values():
            if 'settings' in val:
                val = val['settings']

                if 'index' in val and 'blocks' in val['index'] and 'read_only_allow_delete' in val['index']['blocks']:
                    if json.loads(val['index']['blocks'].get('read_only_allow_delete', 'false')):
                        return True
        return False
