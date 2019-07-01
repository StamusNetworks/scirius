from __future__ import unicode_literals

from datetime import datetime, timedelta
import json
import logging
import socket

from django.conf import settings
from django.template import Context, Template
from django.utils.html import format_html
import urllib2

from rules.models import get_es_address


# ES requests timeout (keep this below Scirius's ajax requests timeout)
es_logger = logging.getLogger('elasticsearch')


class ESQuery(object):
    TIMEOUT = 30
    MAX_RESULT_WINDOW = 10000
    URL = "%s%s/_search?ignore_unavailable=true"

    def __init__(self, request):
        self.request = request

    def _build_es_timestamping(self, date, data='alert'):
        format_table = { 'daily': '%Y.%m.%d', 'hourly': '%Y.%m.%d.%H' }
        now = datetime.now()
        if settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'daily':
            end = now + timedelta(days=1)
        elif settings.ELASTICSEARCH_LOGSTASH_TIMESTAMPING == 'hourly':
            end = now + timedelta(hours=1)
        if data == 'alert':
            base_index = settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX
        elif data == 'host_id':
            base_index = settings.ELASTICSEARCH_LOGSTASH_INDEX + 'host_id-'
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

    def _get_es_url(self, from_date, data='alert'):
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
                else:
                    indexes = settings.ELASTICSEARCH_LOGSTASH_INDEX + "*"
            else:
                start = datetime.fromtimestamp(int(from_date)/1000)
                indexes = self._build_es_timestamping(start, data = data)
        return self.URL % (get_es_address(), indexes)

    def _render_template(self, tmpl, dictionary, qfilter=None):
        if dictionary.get('hosts'):
            hosts = []
            for host in dictionary['hosts']:
                if host != '*':
                    host = format_html('\\"{}\\"', host)
                hosts.append(host)
            dictionary['hosts'] = hosts

        templ = Template(tmpl)
        context = Context(dictionary)
        if qfilter != None:
            query_filter = " AND " + qfilter
            # dump as json but remove quotes since the quotes are already set in templates
            context['query_filter'] = json.dumps(query_filter)[1:-1]
        context['keyword'] = settings.ELASTICSEARCH_KEYWORD
        context['hostname'] = settings.ELASTICSEARCH_HOSTNAME
        return bytearray(templ.render(context), encoding="utf-8")

    def _urlopen(self, url, data=None, method=None, contenttype='application/json'):
        from rules.es_graphs import ESError
        headers = {'content-type': contenttype}
        req = urllib2.Request(url, data, headers)
        if method is not None:
            req.get_method = lambda: method

        try:
            out = urllib2.urlopen(req, timeout=self.TIMEOUT)
        except (urllib2.URLError, urllib2.HTTPError, socket.timeout) as e:
            msg = url + '\n'
            if isinstance(e, socket.timeout):
                msg += 'Request timeout'
            elif isinstance(e, urllib2.HTTPError):
                msg += '%s %s\n%s\n\n%s' % (e.code, e.reason, e, data)
            else:
                msg += repr(e)
            es_logger.exception(msg)
            raise ESError(msg, e)

        out = out.read()
        out = json.loads(out)
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
        if 'composite' not in _query['aggregations'].values()[0]:
            raise Exception('Unexpected aggregation type')

        after = None

        # https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations-bucket-composite-aggregation.html#_after
        while True:
            if after:
                _query['aggregations'].values()[0]['composite']['after'] = after

            _query['aggregations'].values()[0]['composite']['size'] = 1000
            query = bytearray(json.dumps(_query), encoding='utf-8')

            data = self._urlopen(es_url, query)

            yield data

            if 'aggregations' not in data:
                # No data matches the query
                break

            after = data['aggregations'].values()[0].get('after_key')

            if after is None:
                break

    def get(self, *args, **kwargs):
        raise NotImplementedError('get method of ESQuery must be overriden')
