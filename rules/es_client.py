import es_graphs
import es_backend
from django.conf import settings
from es_backend import DEFAULT_COUNT, DEFAULT_ORDER


def create_backend():
    return ESClient()


class ESClient(es_backend.ESBackend):
    def __init__(self):
        es_backend.ESBackend.__init__(self)

    def get_rules_stats_table(self, request, count=DEFAULT_COUNT):
        return es_graphs.ESRulesStats(request).get(count=count, dict_format=False)

    def get_rules_stats_dict(self, request, count=DEFAULT_COUNT):
        return es_graphs.ESRulesStats(request).get(count=count, dict_format=True)

    def get_field_stats_table(self, request, sid, field, field_table_class, count=DEFAULT_COUNT, raw=True):
        if raw:
            # This is some weird elastic stuff
            field += '.' + settings.ELASTICSEARCH_KEYWORD

        return es_graphs.ESFieldStatsAsTable(request).get(sid, field, field_table_class, count=count)

    def get_field_stats_dict(self, request, sid, field, count=DEFAULT_COUNT, raw=True):
        if raw:
            field += '.' + settings.ELASTICSEARCH_KEYWORD

        return es_graphs.ESFieldStats(request).get(sid, field, count=count)

    def get_sid_by_hosts(self, request, sid, count=DEFAULT_COUNT, dict_format=False):
        return es_graphs.ESSidByHosts(request).get(sid, count=count, dict_format=dict_format)

    def get_sid_by_hosts_dict(self, request, sid, count=DEFAULT_COUNT):
        return es_graphs.ESSidByHosts(request).get(sid, count=count, dict_format=True)

    def get_sid_by_hosts_table(self, request, sid, count=DEFAULT_COUNT):
        return es_graphs.ESSidByHosts(request).get(sid, count=count, dict_format=False)

    def get_timeline(self, request, tags=False):
        return es_graphs.ESTimeline(request).get(tags=tags)

    def get_metrics_timeline(self, request, value=None):
        return es_graphs.ESMetricsTimeline(request).get(value=value)

    def get_poststats(self, request, value=None):
        return es_graphs.ESPoststats(request).get(value=value)

    def get_health(self, request):
        return es_graphs.ESHealth(request).get()

    def get_stats(self, request):
        return es_graphs.ESStats(request).get()

    def get_indices_stats(self, request):
        return es_graphs.ESIndicesStats(request).get()

    def get_indices(self, request):
        return es_graphs.ESIndices(request).get()

    def get_rules_per_category(self, request):
        return es_graphs.ESRulesPerCategory(request).get()

    def delete_alerts_by_sid(self, request, sid):
        return es_graphs.ESDeleteAlertsBySid(request).get(sid)

    def get_alerts_count(self, request, prev=0):
        return es_graphs.ESAlertsCount(request).get(prev=prev)

    def get_latest_stats(self, request):
        return es_graphs.ESLatestStats(request).get()

    def get_ippair_alerts(self, request):
        return es_graphs.ESIppairAlerts(request).get()

    def get_ippair_network_alerts(self, request):
        return es_graphs.ESIppairNetworkAlerts(request).get()

    def get_alerts_tail(self, request, search_target=True):
        return es_graphs.ESAlertsTail(request).get(search_target=search_target)

    def get_suri_log_tail(self, request):
        return es_graphs.ESSuriLogTail(request).get()

    def get_top_rules(self, request, count=DEFAULT_COUNT, order=DEFAULT_ORDER):
        return es_graphs.ESTopRules(request).get(count=count, order=order)

    def get_sigs_list_hits(self, request, sids, order=DEFAULT_ORDER):
        return es_graphs.ESSigsListHits(request).get(sids, order=order)

    def get_es_major_version(self):
        return es_graphs.get_es_major_version()
