from __future__ import unicode_literals, print_function, division

import json
import logging
import socket
import urllib2
import ssl
import models
import tables
import django_tables2
import time
import itertools
import operator
from es_backend import ESBackend, DEFAULT_COUNT, DEFAULT_ORDER

import functools
from scirius.utils import parallel_map

from django.conf import settings

humio_logger = logging.getLogger('humio')

ALERTS_FILTER = '"event_type" = "alert"'

HUMIO_ENDPOINT_REPO_QUERY = "/api/v1/repositories/%s/query"
HUMIO_ENDPOINT_STATUS = "/api/v1/status"
HUMIO_DEFAULT_SORT_LIMIT = 20000

FIELD_REPLACEMENTS = {
    'alert.source.ip': 'src_ip',
    'alert.target.ip': 'dest_ip',
    'vlan': 'vlan[0]',  # This is due to problems with lists in Humio
}


def _build_query(filters, hosts=None):
    """
    Build a humio query from a list of filters.

    Filters will be applied according to their order in the filters list.

    :param filters: list of filters (strings)
    :param hosts: list of hosts that we want the query to target
    :return:
    """

    filters = filter(bool, filters)
    filter_query = '|'.join(filters)
    if hosts:
        hosts_query = ' or '.join(map(lambda h: 'host = "%s"' % h.replace('\\', '\\\\').replace('"', '\\"'), hosts))
        return hosts_query + '|' + filter_query
    else:
        return filter_query


def _replace_field_name(field_name):
    res = field_name
    if field_name.endswith('.raw'):
        res = field_name[:-4]
    if field_name.endswith('.keyword'):
        res = field_name[:-8]
    if res in FIELD_REPLACEMENTS:
        res = FIELD_REPLACEMENTS[res]
    return res


def _fix_qfilter(qfilter):
    """
    Fixes elasticsearch based filters to work as humio filters.

    Apply replacements on qfilter to convert filters from the elasticsearch query language to the humio query language.

    :param qfilter:
    :return: updated qfilter
    """

    def fix_single_filter(s):
        split = s.split(':', 1)
        split[0] = _replace_field_name(split[0])
        return '='.join(split)

    if qfilter:
        # Splitting by whitespace and fix all strings of non-whitespace
        # individually is needed to correctly apply boolean functions
        # like NOT, AND, and OR. This is not a very good solution, but
        # since the qfilters used in the scirius codebase is of such
        # simplicity, this shouldn't be a problem. Humio supports
        # NOT, AND and OR.
        return ' '.join(list(map(fix_single_filter, qfilter.split(' '))))


def _parse_sort(sort_param):
    # Parse sort field: [-](hits|sid|msg|category|*)
    if sort_param:
        if sort_param[0] == '-':
            sort_order = 'desc'
            sort_key = sort_param[1:]
        else:
            sort_order = 'asc'
            sort_key = sort_param
    else:
        sort_order = 'asc'
        sort_key = None
    return sort_key, sort_order


def _create_sort_filter(sort_param, sort_key_field_map, limit=HUMIO_DEFAULT_SORT_LIMIT,
                        default_sort_key=None, default_sort_order='desc'):
    """
    Fixes elasticsearch based sorting to work as humio filters

    Map table columns to the humio query field to sort by and a list of humio fields
    to add to a groupBy statement.

    NOTE: Default sort order is used when no sort key is specified.

    :param sort_key_field_map: A dictionary mapping column keys (eg. 'hits' and 'category')
                               to a dict {'groupby_fields' <list of fields>, 'field': <humio field>}
    :return: tuple: (<list of groupby fields>, <sort_filter>)
    """

    sort_key, sort_order = _parse_sort(sort_param)

    if not sort_key:
        if not default_sort_key:
            humio_logger.error('Sort key was None and default_sort_key was None')
            return None
        sort_key = default_sort_key
        sort_order = default_sort_order

    if sort_key not in sort_key_field_map.keys():
        humio_logger.error('Unexpected sort key: %s, not in field_map' % sort_key)
        return None

    sort_order = sort_order or default_sort_order

    map_entry = sort_key_field_map[sort_key]
    groupby_fields, sort_field = map_entry['groupby_fields'], map_entry['field']

    sort_filter = 'sort(field=[%s], limit=%d, order=%s)' % (sort_field, int(limit), sort_order)

    return groupby_fields, sort_filter


def _urlopen(request):
    try:
        out = urllib2.urlopen(request, timeout=settings.HUMIO_TIMEOUT)
    except (urllib2.URLError, socket.timeout) as e:
        msg = unicode(e)
        humio_logger.exception(msg)
        raise RuntimeError(msg)
    return out


def _get_interval(request):
    return int(request.GET['interval']) * 1000 if 'interval' in request.GET else None


def _get_hosts(request):
    if 'hosts' in request.GET:
        return request.GET['hosts'].split(',')
    return []


def _get_qfilter(request):
    return _fix_qfilter(request.GET.get('qfilter', None))


def _get_from_date(request):
    return int(request.GET.get('from_date', 0))


def _get_sort_param(request):
    return request.GET.get('sort', None)


def _get_int(val):
    try:
        return int(val)
    except ValueError:
        try:
            return int(float(val))
        except ValueError:
            return 0


def _chunks(l, n):
    n = max(1, n)
    return (l[i:i+n] for i in xrange(0, len(l), n))


class HumioClient(object, ESBackend):
    def __init__(self):
        super(HumioClient, self).__init__()
        self._api_token = settings.HUMIO_API_TOKEN
        self._host = settings.HUMIO_HOST
        self._repository = settings.HUMIO_REPOSITORY

    def _humio_request(self, endpoint, query_data):
        headers = {
            'content-type': 'application/json',
            'accept': 'application/json',
            'Authorization': 'Bearer ' + self._api_token
        }
        url = self._host + endpoint
        humio_logger.info("Request to %s with data: %s" % (url, query_data))
        req = urllib2.Request(url, query_data, headers=headers)
        res = _urlopen(req)
        data = res.read()
        return data

    def _humio_query(self, filters, start=0, end=None, is_live=False, fix_filters=True, hosts=None):
        """
        Does a humio query with the given parameters.

        :param start: time since epoch in milliseconds
        :param end: time since epoch in milliseconds, string or None
        """
        if not end:
            end = 'now'

        query = {
            'queryString': _build_query(filters, hosts=hosts),
            'start': int(start),
            'end': end,
            'isLive': is_live
        }

        query_data = json.dumps(query)
        api_endpoint = HUMIO_ENDPOINT_REPO_QUERY % self._repository
        res = self._humio_request(api_endpoint, query_data)
        return json.loads(res)

    def _graphql_query(self, query, variables=None):
        data = {
            'query': query,
        }

        query_data = json.dumps(data)
        api_endpoint = '/graphql'

        res = self._humio_request(api_endpoint, query_data)
        return json.loads(res)

    def _create_custom_field_names_filter(self, from_to_dict, drop_old=True):
        """
        Create a humio filter to convert output keys to the ones specified in from_to_dict.

        :param drop_old: drop 'from' keys
        """
        drop_filter = ''
        if drop_old:
            drop_filter = '| drop([%s])' % (','.join(from_to_dict.keys()))

        return '|'.join(['%s := %s' % (v, k) for k, v in from_to_dict.items()]) + drop_filter

    def _get_rule_stats(self, count, from_date, qfilter=None,
                        extra_fields=None, extra_filters=[], hosts=None,
                        sort_param=None):
        """Get the top <count> rules sorted by key <sort_key> and ordered by <sort_order>"""

        if not extra_fields:
            extra_fields = []

        rule_stats_sorting_field_map = {
            'hits':      {'groupby_fields': [],                   'field': '_count'},
            'sid':       {'groupby_fields': [],                   'field': 'alert.signature_id'},
            'msg':       {'groupby_fields': ['alert.signature'],  'field': 'alert.signature'},
            'category':  {'groupby_fields': ['alert.category'],   'field': 'alert.category'},
        }

        groupby_fields, sort_filter = _create_sort_filter(sort_param, rule_stats_sorting_field_map,
                                                          limit=count, default_sort_key='hits')
        fields = extra_fields + ['alert.signature_id'] + groupby_fields

        fields_str = 'field=[' + ','.join(fields) + ']'
        query_str = 'groupBy(%s, function=count())' % fields_str

        return self._humio_query(filters=[ALERTS_FILTER, qfilter, query_str, sort_filter] + extra_filters,
                                 start=from_date, hosts=hosts)

    def get_rules_stats_table(self, request, count=DEFAULT_COUNT):
        hosts = _get_hosts(request)
        from_date = _get_from_date(request)
        qfilter = _get_qfilter(request)
        sort_param = _get_sort_param(request)

        dict_data = self._get_rule_stats(count, from_date, qfilter, hosts=hosts, sort_param=sort_param)

        def rule_from_entry(entry):
            sid = int(entry['alert.signature_id'])
            try:
                rule = models.Rule.objects.get(sid=sid)
                rule.hits = int(entry['_count'])
            except:
                humio_logger.error('Can not find rule with sid {}'.format(sid))
                return None
            return rule

        rules = [rule_from_entry(entry) for entry in dict_data]
        rules_table = tables.ExtendedRuleTable(rules)
        django_tables2.RequestConfig(request).configure(rules_table)
        return rules_table

    def get_rules_stats_dict(self, request, count=DEFAULT_COUNT):
        hosts = _get_hosts(request)
        from_date = _get_from_date(request)
        sort_param = _get_sort_param(request)

        r = self._get_rule_stats(count, from_date, hosts=hosts, sort_param=sort_param)
        return list(map(lambda x: {'doc_count': int(x['_count']), 'key': int(x['alert.signature_id'])}, r))

    def get_field_stats_table(self, request, sid, field, count=DEFAULT_COUNT):
        data = self.get_field_stats_dict(request, sid, field)
        if data is None:
            objects = tables.RuleHostTable([])
            django_tables2.RequestConfig(request).configure(objects)
            return objects
        objects = []
        for elt in data:
            fstat = {'host': elt['key'], 'count': int(elt['doc_count'])}
            objects.append(fstat)
        objects = tables.RuleHostTable(objects)
        django_tables2.RequestConfig(request).configure(objects)
        return objects

    def get_field_stats_dict(self, request, sid, field, count=DEFAULT_COUNT):
        hosts = _get_hosts(request)
        from_date = _get_from_date(request)
        qfilter = _get_qfilter(request)
        field = _replace_field_name(field)
        sort_param = _get_sort_param(request)

        sort_parameter_field_mapping = {
            'count':     {'groupby_fields': [], 'field': 'doc_count'},
            'doc_count': {'groupby_fields': [], 'field': 'doc_count'},
            'host':      {'groupby_fields': [], 'field': 'key'},
            'key':       {'groupby_fields': [], 'field': 'key'}
        }
        _, sort_filter = _create_sort_filter(sort_param, sort_parameter_field_mapping,
                                             limit=count, default_sort_key='count')

        if field:
            field_names = {field: 'key', '_count': 'doc_count'}
        else:
            field_names = {'alert.signature_id': 'key', '_count': 'doc_count'}
        field_names_filter = self._create_custom_field_names_filter(field_names)

        return self._es_get_field_stats_json(sid, field, hosts=hosts, count=count,
                                             from_date=from_date, qfilter=qfilter,
                                             filters=[field_names_filter, sort_filter])

    def _es_get_field_stats_json(self, sid, field, hosts=None, count=20,
                                 from_date=0, qfilter=None, filters=[]):
        if sid:
            query_str = 'alert.signature_id = %s | ' % sid
        else:
            query_str = ''
        query_str += 'groupBy(field=%s, function=count(), limit=%d)' % (field, int(count))
        return self._humio_query(filters=[ALERTS_FILTER, qfilter, query_str] + filters, start=from_date, hosts=hosts)

    def get_sid_by_hosts_dict(self, request, sid, count=DEFAULT_COUNT):
        """
        :return dict on the format {"rule":[{"key":"<host>","doc_count":<alerts on rule with given sid>}]}:
        """
        from_date = _get_from_date(request)
        sort_param = _get_sort_param(request)

        hits_by_hosts_sorting_field_map = {
            'host':  {'groupby_fields': ['host'], 'field': 'host'},
            'count': {'groupby_fields': ['host'], 'field': '_count'},
        }

        groupby_fields, sort_filter = _create_sort_filter(sort_param, hits_by_hosts_sorting_field_map,
                                                          limit=count, default_sort_key='count')

        groupby_field = 'host'
        query_str = 'alert.signature_id = %s | groupBy(%s, function=count())' % (sid, groupby_field)
        data = self._humio_query(filters=[ALERTS_FILTER, query_str, sort_filter], start=from_date)

        # transform from the format:
        # [{host: <host>, _count: <count>}, ...]
        # to
        # {'rule': ['key': <host>, 'doc_count': <count>}, ...]}
        rdata = {'rule': []}
        for b in data:
            entry = {'key': b['host'], 'doc_count': int(b['_count'])}
            rdata['rule'].append(entry)
        return rdata

    def get_sid_by_hosts_table(self, request, sid, count=DEFAULT_COUNT):
        data = self.get_sid_by_hosts_dict(request, sid, count=count)
        rdata = [{'host': e['key'], 'count': e['doc_count']} for e in data['rule']]
        stats = tables.RuleStatsTable(rdata)
        django_tables2.RequestConfig(request).configure(stats)
        return stats

    def get_timeline(self, request, tags=False):
        """Gets timeline data for use in frontend.
        Will use one thread and one query for every chunk of hosts.
        The chunk size is set by settings.HUMIO_TIMELINE_CHUNK_SIZE.
        The precision (buckets) of the timeline is inverse proportional to
        the number of queries needed to complete the timeline.
        """
        hosts = _get_hosts(request)
        from_date = _get_from_date(request)
        interval = _get_interval(request)
        qfilter = _get_qfilter(request)

        chunk_size = settings.HUMIO_TIMELINE_CHUNK_SIZE
        n_queries = len(hosts)//chunk_size

        def parallel_query(from_date, interval, hosts, qfilter, tags, buckets=None):
            chunks = [hosts[s:s+chunk_size] for s in range(0, len(hosts), chunk_size)]

            end_date = int(time.time()) * 1000

            common_kwargs = {'from_date': from_date, 'interval': interval,
                             'qfilter': qfilter, 'tags': tags, 'end_date': end_date,
                             'buckets': buckets}

            def wrapper(i, h, **kwargs):
                return i._get_timeline_sp(hosts=h, **kwargs)

            f = functools.partial(wrapper, self, **common_kwargs)

            def mergedict(x, y):
                x.update(y)
                return x

            result = functools.reduce(mergedict, parallel_map(f, chunks))
            return result

        if n_queries > 2:
            results = parallel_query(from_date, interval, hosts, qfilter, tags, buckets=100//(n_queries))
        else:
            results = self._get_timeline_sp(from_date, interval, hosts, qfilter, tags, buckets=100)
        return results

    def _get_timeline_sp(self, from_date=0, interval=None, hosts=None, qfilter=None, tags=False, end_date=None, buckets=None):
        """Gets a list of alert counts at a given interval from the given from date.
        :param buckets: the amount of alert count points per host to have on the timeline
        :return dict on the form:
        {
         'from_date': <from_date>,
         'interval': <interval>,
          <host>: {entries: [{time: <bucket>, count: <count>}]},
          ...
        }
        :
        """
        if not buckets:
            buckets = 100

        from_date = int(from_date)

        if not interval:
            interval = int((time.time() - (int(from_date) / 1000)) / buckets) * 1000

        query_str = 'bucket(field=[host], function=count(), span=%sms) | sort(host, limit=%d)' % (interval, HUMIO_DEFAULT_SORT_LIMIT)

        data = self._humio_query(filters=[ALERTS_FILTER, qfilter, query_str], start=from_date, hosts=hosts, end=end_date)

        # transform from the format:
        # [{host: <host>, _count: <count>, _bucket: <bucket>}, ...]
        # to
        # {<host>: {entries: {time: <bucket>, count: <count>}}
        rdata = {key: {'entries': [{
            'time': int(v['_bucket']),
            'count': int(v['_count'])
        } for v in values]}
            for key, values in itertools.groupby(data, key=operator.itemgetter('host'))}

        empty_series = [{'time': from_date, 'count': 0}, {'time': int(time.time() * 1000), 'count': 0}]

        if hosts:
            for host in hosts:
                if host not in rdata:
                    rdata[host] = {'entries': empty_series}

        rdata['from_date'] = int(from_date)
        rdata['interval'] = int(interval)
        return rdata

    def _get_timeline_data_for_signatures(self, request, sids):
        from_date = _get_from_date(request)
        interval = _get_interval(request)
        qfilter = _get_qfilter(request)
        end = int(time.time()) * 1000

        if not interval:
            buckets = 100
            interval = int((time.time() - (int(from_date) / 1000)) / buckets) * 1000

        r_data = {}
        max_bucket_series = 50  # Humio can only generate so many bucket series in a query

        query_str = 'bucket(field=alert.signature_id, span=%sms, limit=%d)' \
                    '| not _count = 0' \
                    '| sort(alert.signature_id, limit=%d)' % (interval, max_bucket_series, HUMIO_DEFAULT_SORT_LIMIT)

        # Divide the list of sids into chunks of size max_bucket_series
        for sids_chunk in _chunks(sids, max_bucket_series):
            sid_filter = " or ".join(["alert.signature_id = %s" % sid for sid in sids_chunk])
            timeline_data = self._humio_query(filters=[ALERTS_FILTER, qfilter, sid_filter, query_str], start=from_date)
            r_data.update({
                sid: {
                    'timeline_data': [
                        {'date': int(bucket['_bucket']), 'hits': int(bucket['_count'])} for bucket in buckets_for_sid
                    ]
                } for sid, buckets_for_sid in itertools.groupby(timeline_data,
                                                                key=operator.itemgetter('alert.signature_id'))
            })

        def fill_series(series_entry):
            dates = set(map(operator.itemgetter('date'), series_entry['timeline_data']))
            for t in range(from_date, end, interval):
                if t not in dates:
                    series_entry['timeline_data'].append({
                        'date': t,
                        'hits': 0
                    })
            return series_entry

        return {k: fill_series(v) for k, v in r_data.iteritems()}

    def get_signature_timeline_and_probe_hits(self, request, sids):
        sids = map(unicode, sids)
        from_date = _get_from_date(request)
        qfilter = _get_qfilter(request)

        # First get the timeline for each signature
        r_data = self._get_timeline_data_for_signatures(request, sids)

        # Then get the hits per probe per signature
        sid_filter = " or ".join(["alert.signature_id = %s" % sid for sid in sids])
        query_str = 'groupby(field=[host, alert.signature_id], limit=%d)' \
                    '| sort(field=[alert.signature_id, host], limit=%d)' % (HUMIO_DEFAULT_SORT_LIMIT,
                                                                            HUMIO_DEFAULT_SORT_LIMIT)
        probe_data = self._humio_query(filters=[ALERTS_FILTER, sid_filter, qfilter, query_str], start=from_date)
        for sid, probe_entries in itertools.groupby(probe_data, key=operator.itemgetter('alert.signature_id')):
            r_data[sid]['probes'] = [{
                'probe': probe['host'],
                'hits': int(probe['_count'])
            } for probe in probe_entries]
            r_data[sid]['hits'] = sum(map(lambda x: x['hits'], r_data[sid]['probes']))

        # If a signature had no alerts, make sure to include the empty entry.
        for sid in sids:
            if sid not in r_data:
                r_data[sid] = {
                    'hits': 0,
                    'probes': [],
                    'timeline_data': []
                }
        return r_data

    def get_rules_per_category(self, request):
        """Gets a list of alerted rules grouped into categories from humio.

        :param request: request object with get parameters
        :return dict on the form:
            {'key': 'categories',
                 'children': [
                    {'doc_count': <alert count for rules in this category>,
                      'children': [
                        {'key': <sid>, 'msg': <rule msg>, 'doc_count': <rule alert count>},
                        {'key': <sid>, 'msg': <rule msg>, 'doc_count': <rule alert count>},
                          ...
                      ],
                    },
                    {'doc_count': <alert count for rules in this category>,
                      'children': [
                        {'key': <sid>, 'msg': <rule msg>, 'doc_count': <rule alert count>},
                        {'key': <sid>, 'msg': <rule msg>, 'doc_count': <rule alert count>},
                          ...
                      ],
                    },
                    ...
                 ]
             }
                    :
        """
        hosts = _get_hosts(request)
        from_date = _get_from_date(request)
        qfilter = _get_qfilter(request)

        # This query groups alert signatures, counts them, and then
        # groups the result by category, collecting the alerts into
        # a list-like result.
        # This query will be changed to one utilizing sub-queries
        # when these become available in humio.

        query_str = """
        select([alert.signature_id, alert.category, alert.signature])
        | groupBy(
                [alert.signature_id, alert.category, alert.signature],
                function=count(as="doc_count"))
        | msg := alert.signature | key := alert.signature_id
        | drop([alert.signature, alert.signature_id])
        | groupBy(
                alert.category,
                function=[
                        count(as="total_count"),
                        collect([key, msg, doc_count], multival=false, maxlen=200000)])
        | drop(@rawstring)
        """

        cdata = self._humio_query(filters=[ALERTS_FILTER, qfilter, query_str], start=from_date, hosts=hosts)

        def get_children_from_entry(e):
            children = [{} for _ in range(int(e['total_count']))]
            for index, field, value in map(lambda (i, f, v): (int(i), f, v),
                                       map(lambda (k, v): (k[8:k.index(']')], k[k.index(']') + 2:], v),
                                       filter(lambda (k, v): k.startswith('_events'), e.items()))):
                children[index][field] = int(value) if field in ['key', 'doc_count'] else value
            return children

        def sum_total(entry):
            entry['doc_count'] = sum(int(e['doc_count']) for e in entry['children'])
            return entry

        rdata = {
            'key': 'categories',
            'children': list(map(sum_total, [
                {
                    'key': entry['alert.category'],
                    'children': get_children_from_entry(entry)
                }
                for entry in cdata
            ]))
        }
        return rdata

    def get_alerts_count(self, request, prev=0):
        """Gets the previous alert count and the current alert count.

        :return: {'prev_doc_count': <previous>, 'doc_count' <current>}
        """

        hosts = _get_hosts(request)
        from_date = _get_from_date(request)
        qfilter = _get_qfilter(request)

        # FIXME: Currently does two queries, one for doc_count and one for prev_doc_count.
        from_date_ms = int(int(from_date)//1000)*1000
        current_time_ms = int(time.time())*1000
        diff_ms = (current_time_ms - from_date_ms)
        prev_start_ms = (from_date_ms - diff_ms)
        query_str = 'count()'

        filters = [ALERTS_FILTER, qfilter, query_str]
        data = self._humio_query(filters=filters, start=from_date_ms, hosts=hosts)
        cur_count = int(data[0]['_count'])

        if prev and from_date > 0:
            try:
                prev_data = self._humio_query(filters=filters, start=prev_start_ms, end=from_date_ms, hosts=hosts)
                return {'doc_count': cur_count, 'prev_doc_count': int(prev_data[0]['_count'])}
            except:
                humio_logger.error("Unable to get alerts for previous period")
                return {'doc_count': cur_count, 'prev_doc_count': 0}
        else:
            return {'doc_count': cur_count}

    def get_es_major_version(self):
        return settings.HUMIO_SPOOF_ES_VERSION

    def get_metrics_timeline(self, request, value=None):
        hosts = _get_hosts(request)
        from_date = _get_from_date(request)
        from_date = int(from_date)
        interval = _get_interval(request)
        if not interval:
            buckets = 50
            interval = int((time.time() - (int(from_date) / 1000)) / buckets) * 1000

        query_str = """event_type = stats
        | bucket(field=[host], span=%sms, function=stats(function=avg(field="%s")))""" % (interval, value)
        data = self._humio_query(filters=[query_str], start=from_date, hosts=hosts)

        # transform from the format:
        # [{host: <host>, _avg: <avg>, _bucket: <bucket>}, ...]
        # to
        # {<host>: {entries: {time: <bucket>, mean: <mean>}}
        rdata = {key: {'entries': [{
            'time': int(v['_bucket']),
            'mean': _get_int(v['_avg'] if '_avg' in v else 0)
        } for v in values]}
            for key, values in itertools.groupby(data, key=operator.itemgetter('host'))}

        empty_series = [{'time': from_date, 'mean': 0}, {'time': int(time.time() * 1000), 'mean': 0}]

        for host in hosts:
            if host not in rdata:
                rdata[host] = {'entries': empty_series}

        rdata['from_date'] = int(from_date)
        rdata['interval'] = int(interval)
        return rdata

    def get_poststats(self, request, value=None):
        raise NotImplementedError()

    def get_health(self, request):
        status_data = self.get_status()
        graphql_query = """
        {
            cluster {
                nodes {id}
            }
            runningQueries {
                id
                totalWork
                workDone
            }
            meta {
                version clusterId
            }
            repositories {
                id
                name
                description
                uncompressedByteSize
                compressedByteSize
            }
        }
        """
        try:
            res = self._graphql_query(graphql_query)
            data = res['data']
        except:
            data = {}

        def sum_by_key(lst, key):
            return sum([e.get(key, 0) for e in lst])

        repositories = data.get('repositories', [])
        repo = {}
        for r in repositories:
            if r['name'] == self._repository:
                repo = r
                break

        cluster_id = 'unknown'
        if 'meta' in data:
            cluster_id = data['meta'].get('clusterId', 'unknown')

        num_nodes = 0
        if 'cluster' in data:
            num_nodes = len(data['cluster'].get('nodes', []))

        running_queries = data.get('runningQueries', [])
        num_tasks = len(data.get('runningQueries', []))

        health_res = {
            # Part of elasticsearch result
            'cluster_name': cluster_id,
            'status': 'green' if status_data['status'] == 'ok' else 'red',
            'timed_out': False,
            'number_of_nodes': num_nodes,
            'number_of_data_nodes': 0,
            'active_primary_shards': 0,
            'active_shards': 0,
            'relocating_shards': 0,
            'initializing_shards': 0,
            'unassigned_shards': 0,
            'delayed_unassigned_shards': 0,
            'number_of_pending_tasks': num_tasks,
            'number_of_in_flight_fetch': 0,
            'task_max_waiting_in_queue_millis': 0,
            'active_shards_percent_as_number': 0,

            # Additional humio details
            'repository_name': self._repository,
            'repository_description': repo.get('description', ''),
            'repository_uncompressed_size': repo.get('uncompressedByteSize', 0),
            'repository_compressed_size': repo.get('compressedByteSize', 0),
            'repository_id': repo.get('id', 'unknown'),

            'cluster_compressed_size': sum_by_key(repositories, 'compressedByteSize'),
            'cluster_uncompressed_size': sum_by_key(repositories, 'uncompressedByteSize'),
            'cluster_total_work': sum_by_key(running_queries, 'totalWork'),
            'cluster_work_done': sum_by_key(running_queries, 'workDone'),
        }
        return health_res

    def get_stats(self, request):
        raise NotImplementedError()

    def get_indices_stats(self, request):
        raise NotImplementedError()

    def get_indices(self, request):
        raise NotImplementedError()

    def delete_alerts_by_sid(self, request, sid):
        raise NotImplementedError()

    def get_latest_stats(self, request):
        raise NotImplementedError()

    def get_ippair_alerts(self, request):
        raise NotImplementedError()

    def get_ippair_network_alerts(self, request):
        raise NotImplementedError()

    def get_alerts_tail(self, request, search_target=True):
        """Gets and returns the raw alert data for the last 100 alerts"""

        hosts = _get_hosts(request)
        from_date = _get_from_date(request)
        qfilter = _get_qfilter(request)
        count = 100
        query_str = "tail(limit=%d) | select(@rawstring)" % count

        # NOTE: qfilter is applied before query_str because we want to filter
        # on the last 100 alerts matching that filter.
        data = self._humio_query(filters=[ALERTS_FILTER, qfilter, query_str],
                                 hosts=hosts, start=from_date)
        rdata = [{'_id': i, '_source': json.loads(d['@rawstring'])} for i, d in enumerate(data)]
        return rdata

    def get_suri_log_tail(self, request):
        raise NotImplementedError()

    def get_top_rules(self, request, count=DEFAULT_COUNT, order=DEFAULT_ORDER):
        hosts = _get_hosts(request)
        from_date = _get_from_date(request)
        qfilter = _get_qfilter(request)
        count = min(20000, count)

        query_str = "groupBy(alert.signature_id, limit=%d) | sort(_count, limit=%d, order=%s)" % (count, count, order)

        field_names = {'alert.signature_id': 'key', '_count': 'doc_count'}
        field_names_filter = self._create_custom_field_names_filter(field_names)

        data = self._humio_query(filters=[ALERTS_FILTER, qfilter, query_str, field_names_filter],
                                 hosts=hosts, start=from_date)
        return data

    def get_sigs_list_hits(self, request, sids, order=DEFAULT_ORDER):
        hosts = _get_hosts(request)
        from_date = _get_from_date(request)
        qfilter = _get_qfilter(request)

        sid_filter = " or ".join(map(lambda s: "alert.signature_id = %s" % s, sids))

        field_names = {'alert.signature_id': 'key', '_count': 'doc_count'}
        field_names_filter = self._create_custom_field_names_filter(field_names)

        query_str = "groupBy(alert.signature_id) | sort(alert.signature_id, order=%s)" % order

        data = self._humio_query(filters=[ALERTS_FILTER, sid_filter, qfilter, query_str, field_names_filter],
                                 hosts=hosts, start=from_date)
        return data

    def get_status(self):
        try:
            url = self._host + HUMIO_ENDPOINT_STATUS
            req = urllib2.Request(url)
            res = _urlopen(req)
            data = json.loads(res.read())
        except:
            data = {'status': 'not ok', 'version': 'unknown'}
        return data
