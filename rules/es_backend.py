DEFAULT_COUNT = 20
DEFAULT_ORDER = 'desc'

class ESBackend:
    """ESBackend defines the common interface for ElasticSearch like functionality.

    Currently implemented by ESClient and HumioClient.
    """

    def __init__(self):
        pass

    def get_rules_stats_table(self, request, count=DEFAULT_COUNT):
        raise NotImplementedError()

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

    def get_rules_per_category(self, request):
        raise NotImplementedError()

    def delete_alerts_by_sid(self, request, sid):
        raise NotImplementedError()

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
        raise NotImplementedError()

    # NOTE: There are several es_* functions that are not implemented.
