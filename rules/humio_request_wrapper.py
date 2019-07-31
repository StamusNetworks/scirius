from __future__ import print_function, division
import humio_client
from humio_client import HumioClient
from es_backend import ESBackend, DEFAULT_COUNT, DEFAULT_ORDER
import json
from django.utils.safestring import mark_safe

from functools import wraps, partial

def create_args_kwargs(request, args_keys, kwargs_keys):
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
            hosts.append(host)

    context = {
        'hosts': hosts,
        'qfilter': humio_client._fix_qfilter(qfilter),
        'sid': request.GET.get('sid', None),
        'from_date': int(request.GET.get('from_date', 0)),
        'to_date': request.GET.get('to_date', None),
        'count': request.GET.get('count', DEFAULT_COUNT),
    }

    if request.GET.has_key('sort'):
        context['sort_order'] = request.GET.get('sort')
        context['sort_param'] = context['sort_order']
    else:
        # This only works at index.html for now
        context['sort_order'] = '-hits'
        context['sort_param'] = '-hits'

    args = []
    for k in args_keys:
        if k == 'request':
            args.append(request)
            continue
        args.append(context[k])

    kwargs = {}
    for k in kwargs_keys:
        if k in context:
            kwargs[k] = context[k]
    print('CREATE_ARGS_KWARGS', args_keys, kwargs_keys, args, kwargs)
    return (args, kwargs)

def wraps_client(args_keys, kwargs_keys):
    def decorator(f):
        @wraps(f)
        def callee(self_, request, *args, **kwargs):
            args_, kwargs_ = create_args_kwargs(request, args_keys, kwargs_keys)
            client_func = getattr(self_.client, f.__name__)

            # Keep provided positional arguments (overwrite)
            for i in range(len(args)):
                args_[i] = args[i]

            # Keep provided keyword arguments
            kwargs_.update(kwargs)

            print('calling with', args_, kwargs_)
            return client_func(*args_, **kwargs_)
        return callee
    return decorator


class HumioClientRequestWrapper(ESBackend):
    def __init__(self):
        ESBackend.__init__(self)
        self.client = HumioClient()
        print("======= INIT HUMIOCLIENTWRAPPER")

    @wraps_client(['request'], ['hosts', 'count', 'from_date', 'qfilter', 'sort_order', 'sort_key'])
    def get_rules_stats_table(self, request, count=DEFAULT_COUNT):
        pass

    @wraps_client(['request'], ['hosts', 'count', 'from_date', 'qfilter', 'sort_order', 'sort_key'])
    def get_rules_stats_dict(self, request, count=DEFAULT_COUNT):
        pass

    @wraps_client(['request', 'field', 'field_table_class'], ['hosts', 'key', 'count', 'from_date', 'qfilter', 'raw'])
    def get_field_stats_table(self, request, ksid, field, field_table_class, count=DEFAULT_COUNT, raw=False):
        pass

    @wraps_client(['request', 'field'], ['hosts', 'key', 'count', 'from_date', 'qfilter', 'raw'])
    def get_field_stats_dict(self, request, sid, field, field_table_class, count=DEFAULT_COUNT, raw=False):
        pass

    @wraps_client(['request', 'sid'], ['count', 'from_date', 'dict_format', 'sort_key', 'sort_order'])
    def get_sid_by_hosts(self, request, sid, count=DEFAULT_COUNT, dict_format=False):
        pass

    @wraps_client(['request', 'sid'], ['count', 'from_date', 'sort_key', 'sort_order'])
    def get_sid_by_hosts_dict(self, request, sid, count=DEFAULT_COUNT):
        pass

    @wraps_client(['request', 'sid'], ['count', 'from_date', 'sort_key', 'sort_order'])
    def get_sid_by_hosts_table(self, request, sid, count=DEFAULT_COUNT):
        pass

    @wraps_client([], ['from_date', 'interval', 'hosts', 'qfilter', 'tags'])
    def get_timeline(self, request, tags=False):
        pass

    # NOT IMPLEMENTED
    # TODO: Set default 'value' in implementation
    def get_metrics_timeline(self, request, value=None):
        raise NotImplementedError()

    # NOT IMPLEMENTED
    # TODO: Set default 'value' in implementation
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

    @wraps_client([], ['from_date', 'hosts', 'qfilter'])
    def get_rules_per_category(self, request):
        raise NotImplementedError()

    def delete_alerts_by_sid(self, request, sid):
        raise NotImplementedError()

    @wraps_client([], ['from_date', 'hosts', 'qfilter', 'prev'])
    def get_alerts_count(self, request, prev=0):
        raise NotImplementedError()

    def get_latest_stats(self, request):
        raise NotImplementedError()

    def get_ippair_alerts(self, request):
        raise NotImplementedError()

    def get_ippair_network_alerts(self, request):
        raise NotImplementedError()

    def get_alerts_tail(self, request, search_target=True):
        raise NotImplementedError()

    # NOTE: Renamed from suri_log_tail => get_suri_log_tail
    def get_suri_log_tail(self, request):
        raise NotImplementedError()

    def get_top_rules(self, request, count=DEFAULT_COUNT, order=DEFAULT_ORDER):
        raise NotImplementedError()

    def get_sigs_list_hits(self, request, sids, order=DEFAULT_ORDER):
        raise NotImplementedError()

    def get_es_major_version(self):
        return self.client.get_es_major_version()

    # NOTE: There are several es_* functions that are not implemented.
