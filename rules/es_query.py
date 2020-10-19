

from datetime import datetime, timedelta
from time import time
import json
import logging
import socket

from django.conf import settings
from django.template import Context, Template
from django.utils.safestring import mark_safe
import urllib.request
import urllib.error
import urllib.parse

from rules.models import get_es_address
from scirius.utils import get_middleware_module


# ES requests timeout (keep this below Scirius's ajax requests timeout)
es_logger = logging.getLogger('elasticsearch')


def es_string_escape(s):
    if s is None:
        return None
    elif isinstance(s, int):
        return s
    elif isinstance(s, list):
        return [es_string_escape(_s) for _s in s]
    elif isinstance(s, dict):
        _dict = {}
        for key, val in s.items():
            _dict[key] = es_string_escape(val)
        return _dict
    elif not isinstance(s, str):
        raise Exception('Unsupported datatype %s' % s.__class__.__name__)
    return mark_safe(json.dumps(s)[1:-1])


class ESQuery(object):
    TIMEOUT = 30
    MAX_RESULT_WINDOW = 10000
    URL = "%s%s/_search?ignore_unavailable=true"
    INTERVAL_POINTS = 100

    def __init__(self, request):
        self.request = request

    def _build_es_timestamping(self, date, data='alert'):
        format_table = {'daily': '%Y.%m.%d', 'hourly': '%Y.%m.%d.%H'}
        now = datetime.now()
        if settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'daily':
            end = now + timedelta(days=1)
        elif settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'hourly':
            end = now + timedelta(hours=1)
        if data == 'alert':
            base_index = settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX
        elif data == 'host_id':
            base_index = settings.ELASTICSEARCH_LOGSTASH_INDEX + 'host_id-'
        elif data == 'metricbeat':
            base_index = 'metricbeat-'
        elif data == 'stamus':
            base_index = 'stamus-'
        elif data == 'all':
            base_index = '%s*-' % settings.ELASTICSEARCH_LOGSTASH_INDEX
        else:
            base_index = settings.ELASTICSEARCH_LOGSTASH_INDEX
        try:
            indexes = []
            while date < end:
                indexes.append("%s%s*" % (base_index, date.strftime(format_table[settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING])))
                if settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'daily':
                    date += timedelta(days=1)
                elif settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'hourly':
                    date += timedelta(hours=1)
            if len(indexes) > 20:
                return base_index + '2*'
            return ','.join(indexes)
        except:
            return base_index + '2*'

    def _get_es_url(self, data='alert', from_date=None):
        if from_date is None:
            from_date = 0
            if self.request and 'from_date' in self.request.GET:
                from_date = self._from_date()

        if (data == 'alert' and '*' in settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX) or (data != 'alert' and '*' in settings.ELASTICSEARCH_LOGSTASH_INDEX):
            if data == 'alert':
                indexes = settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX
            else:
                indexes = settings.ELASTICSEARCH_LOGSTASH_INDEX
        else:
            if from_date == 0:
                if data == 'alert':
                    indexes = settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX + "*"
                elif data == 'host_id':
                    indexes = settings.ELASTICSEARCH_LOGSTASH_INDEX + "host_id-*"
                elif data == 'metricbeat':
                    indexes = 'metricbeat-*'
                elif data == 'stamus':
                    indexes = settings.ELASTICSEARCH_LOGSTASH_INDEX + 'stamus-*'
                else:
                    indexes = settings.ELASTICSEARCH_LOGSTASH_INDEX + "*"
            else:
                start = datetime.fromtimestamp(int(from_date) / 1000)
                indexes = self._build_es_timestamping(start, data=data)
        return self.URL % (get_es_address(), indexes)

    def _from_date(self, params=None):
        if params and 'from_date' in params:
            return params['from_date']
        elif self.request and 'from_date' in self.request.GET:
            from_date = int(self.request.GET['from_date'])
        else:
            # 30 days ago
            from_date = (time() - (30 * 24 * 60 * 60)) * 1000

        if from_date >= self._to_date():
            # Asking for a date in the future (browser of the user has clock out of sync), return last hour
            from_date = self._to_date() - (60 * 60 * 1000)

        return from_date

    def _to_date(self, params=None, es_format=False):
        to_date = 'now'
        if params and 'to_date' in params:
            return params['to_date']
        elif self.request and 'to_date' in self.request.GET:
            if self.request.GET['to_date'] != 'now':
                to_date = int(self.request.GET['to_date'])

        if to_date == 'now':
            if es_format:
                return '"now"'
            else:
                return time() * 1000
        return to_date

    def _interval(self, dictionary=None):
        if dictionary and 'interval' in dictionary:
            interval = int(dictionary['interval']) * 1000
        elif self.request and 'interval' in self.request.GET:
            interval = int(self.request['interval']) * 1000
        else:
            interval = int((self._to_date() - self._from_date()) / self.INTERVAL_POINTS)

        if interval < 1:
            return 1

        return interval

    def _render_template(self, tmpl, _dictionary, ignore_middleware=False):
        dictionary = es_string_escape(_dictionary)
        hosts = ['*']
        qfilter = None

        if self.request:
            if 'hosts' in self.request.GET:
                hosts = es_string_escape(self.request.GET['hosts']).split(',')
            else:
                if 'hosts' in dictionary:
                    hosts = dictionary['hosts'].split(',')
            if 'qfilter' in self.request.GET:
                qfilter = es_string_escape(self.request.GET['qfilter'])
        else:
            if 'qfilter' in dictionary:
                qfilter = dictionary['qfilter']

        hosts_filter = None
        if hosts == ['*']:
            # use _exists_ in case analyze_wildcard is false
            hosts_filter = '_exists_:%s' % settings.ELASTICSEARCH_HOSTNAME
        else:
            hosts_filter = ['%s:%s' % (settings.ELASTICSEARCH_HOSTNAME, h) for h in hosts]
            hosts_filter = mark_safe('(%s)' % ' '.join(hosts_filter))

        query_filter = get_middleware_module('common').es_query_string(self.request)

        if qfilter is not None:
            query_filter += ' AND ' + qfilter
            query_filter = mark_safe(query_filter)

        if ignore_middleware:
            bool_clauses = ''
        else:
            bool_clauses = get_middleware_module('common').es_bool_clauses(self.request)

        templ = Template(tmpl)
        context = Context(dictionary)
        context.update({
            'hosts': hosts,
            'hosts_filter': hosts_filter,
            'keyword': settings.ELASTICSEARCH_KEYWORD,
            'hostname': settings.ELASTICSEARCH_HOSTNAME,
            'timestamp': settings.ELASTICSEARCH_TIMESTAMP,
            'from_date': self._from_date(dictionary),
            'to_date': mark_safe(self._to_date(dictionary, es_format=True)),  # mark quotes around "now" as safe
            'query_filter': query_filter,
            'bool_clauses': bool_clauses,
            'interval': str(self._interval(dictionary)) + 'ms'
        })

        return bytearray(templ.render(context), encoding="utf-8")

    def _urlopen(self, url, data=None, method=None, contenttype='application/json'):
        from rules.es_graphs import ESError
        headers = {'content-type': contenttype}
        if isinstance(data, str):
            data = data.encode('utf-8')

        req = urllib.request.Request(url, data, headers)
        if method is not None:
            req.get_method = lambda: method

        try:
            out = urllib.request.urlopen(req, timeout=self.TIMEOUT)
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout) as e:
            msg = url + '\n'
            if isinstance(e, socket.timeout):
                msg += 'Request timeout'
            elif isinstance(e, urllib.error.HTTPError):
                msg += '%s %s\n%s\n\n%s\n%s' % (e.code, e.reason, e, data, e.read())
            else:
                msg += repr(e)
            es_logger.exception(msg)

            if settings.DEBUG:
                raise ESError(msg, e)
            else:
                raise ESError('Elasticsearch error %s %s' % (e.code, e.reason), e)
        else:
            if settings.DEBUG:
                if method is None:
                    if data:
                        method = 'POST'
                    else:
                        method = 'GET'
                if data:
                    data = '-- ' + data.decode('utf-8').replace('\n', '\n-- ')
                else:
                    data = '-- No data'
                es_logger.info('%s %s\n%s' % (method, url, data))

        out = out.read()
        out = json.loads(out.decode('utf-8'))
        return out

    def _scroll_query(self, es_url, query):
        count = None
        scroll_id = None

        # Make a "scroll" query to read all answers
        while count is None or count > 0:
            data = self._urlopen(es_url, query)
            yield data

            if scroll_id is None:
                if '_scroll_id' not in data:
                    # No data matches the query
                    break
                scroll_id = data['_scroll_id']
                count = data['hits']['total']
                es_url = get_es_address() + '_search/scroll'
                query = bytearray('{"scroll": "1m", "scroll_id": "%s"}' % scroll_id, encoding='utf-8')

            count -= self.MAX_RESULT_WINDOW

        # Remove the "scroll"
        if scroll_id:
            url = get_es_address() + '_search/scroll'
            query = '{"scroll_id": "%s"}' % scroll_id
            self._urlopen(url, query, method='DELETE')

    def _scroll_composite(self, es_url, query):
        _query = json.loads(query.decode('utf-8'))
        if 'aggregations' not in _query:
            raise Exception('Missing aggregation')
        if len(_query['aggregations']) != 1:
            raise Exception('Unexpected aggregation count')
        if 'composite' not in list(_query['aggregations'].values())[0]:
            raise Exception('Unexpected aggregation type')

        after = None

        # https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations-bucket-composite-aggregation.html#_after
        while True:
            if after:
                list(_query['aggregations'].values())[0]['composite']['after'] = after

            list(_query['aggregations'].values())[0]['composite']['size'] = 10000
            query = bytearray(json.dumps(_query), encoding='utf-8')

            data = self._urlopen(es_url, query)

            yield data

            if 'aggregations' not in data:
                # No data matches the query
                break

            after = list(data['aggregations'].values())[0].get('after_key')

            if after is None:
                break

    def get(self, *args, **kwargs):
        raise NotImplementedError('get method of ESQuery must be overriden')
