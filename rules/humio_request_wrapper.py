from __future__ import print_function, division
import humio_client
from humio_client import HumioClient
from es_backend import ESBackend, DEFAULT_COUNT, DEFAULT_ORDER
import json
from django.utils.safestring import mark_safe


def create_context_dict(request, keys=None):
    print("======= CREATECONTEXTDICT HUMIOCLIENTWRAPPER")
    hosts_list = []
    qfilter = None

    if request:
        if 'hosts' in request.GET:
            hosts_list = request.GET['hosts'].split(',')
        if 'qfilter' in request.GET:
            qfilter = request.GET['qfilter']

    hosts = []
    for host in hosts_list:
        if host != '*':
            host = json.dumps(host).replace('"', '\\"')
            host = mark_safe(host)
            hosts.append(host)

    context = {
        'hosts': hosts,
        'qfilter': humio_client._fix_qfilter(qfilter),
        'sid': request.GET.get('sid', None),
        'from_date': int(request.GET.get('from_date', 0)),
        'to_date': request.GET.get('to_date', None),
        'count': request.GET.get('count', DEFAULT_COUNT),
    }

    # FIXME: This would seem to be redundant since humio_client._fix_sorting sets default
    # values, but the default ordering is not passed back and thus not set as context
    # variables. As a temporary fix, this makes it so that the correct sorting used
    # is shown at the table column 'hits' (descending).
    if request.GET.has_key('sort'):
        context['sort_order'] = request.GET.get('sort')
        context['sort_param'] = context['sort_order']
    else:
        # This only works at index.html for now
        context['sort_order'] = '-hits'
        context['sort_param'] = '-hits'

    if keys:
        c = {}
        for k, v in context.items():
            if k in keys:
                c[k] = v
        print(c)
        return c

    return context


class HumioClientRequestWrapper(ESBackend):
    def __init__(self):
        ESBackend.__init__(self)
        self.client = HumioClient()
        print("======= INIT HUMIOCLIENTWRAPPER")

    def get_rules_stats_table(self, request, count=DEFAULT_COUNT):
        c = create_context_dict(request, keys=['hosts', 'count', 'from_date', 'qfilter', 'sort_order', 'sort_key'])
        return self.client.get_rules_stats_table(request, **c)

    def get_rules_stats_dict(self, request, count=DEFAULT_COUNT):
        raise NotImplementedError()

    def get_field_stats_table(self, request, ksid, field, field_table_class, count=DEFAULT_COUNT, raw=False):
        raise NotImplementedError()

    def get_field_stats_dict(self, request, sid, field, field_table_class, count=DEFAULT_COUNT, raw=False):
        raise NotImplementedError()

    def get_sid_by_hosts(self, request, sid, count=DEFAULT_COUNT, dict_format=False):
        raise NotImplementedError()

    def get_sid_by_hosts_dict(self, request, sid, count=DEFAULT_COUNT):
        raise NotImplementedError()

    def get_sid_by_hosts_table(self, request, sid, count=DEFAULT_COUNT):
        raise NotImplementedError()

    def get_timeline(self, request, tags=False):
        raise NotImplementedError()

    def get_metrics_timeline(self, request, value=None):
        raise NotImplementedError()

    def get_poststats(self, request, value=None):
        raise NotImplementedError()

    def get_health(self, request):
        raise NotImplementedError()

    def get_stats(self, request):
        raise NotImplementedError()

    def get_indices_stats(self, request):
        raise NotImplementedError()

    def get_indices(self, request):
        raise NotImplementedError()

    def get_rules_per_category(self, request):
        raise NotImplementedError()

    def delete_alerts_by_sid(self, request, sid):
        raise NotImplementedError()

    def get_alerts_count(self, request, prev=0):
        c = create_context_dict(request, keys=['from_date', 'hosts', 'qfilter'])
        c['prev'] = prev
        return self.client.get_alerts_count(**c)

    def get_latest_stats(self, request):
        raise NotImplementedError()

    def get_ippair_alerts(self, request):
        raise NotImplementedError()

    def get_ippair_network_alerts(self, request):
        raise NotImplementedError()

    def get_alerts_tail(self, request, search_target=True):
        raise NotImplementedError()

    def get_suri_log_tail(self, request):
        raise NotImplementedError()

    def get_top_rules(self, request, count=DEFAULT_COUNT, order=DEFAULT_ORDER):
        raise NotImplementedError()

    def get_sigs_list_hits(self, request, sids, order=DEFAULT_ORDER):
        raise NotImplementedError()

    def get_es_major_version(self):
        return self.client.get_es_major_version()
