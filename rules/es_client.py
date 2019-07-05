import es_graphs
import es_backend
from django.conf import settings

def create_backend():
    return ESClient()

class ESClient(es_backend.ESBackend):
    def __init__(self):
        es_backend.ESBackend.__init__(self)

    def get_rules_stats_dict(self, request, hosts=None,
                             count=20, from_date=0, qfilter=None,
                             sort_order=None, sort_key=None):
        return es_graphs.es_get_rules_stats(request, hosts[0] if hosts else None, count=count, from_date=from_date,
                                            qfilter=qfilter, dict_format=True)

    def get_rules_stats_table(self, request, hosts=None,
                              count=20, from_date=0, qfilter=None,
                              sort_order=None, sort_key=None):
        return es_graphs.es_get_rules_stats(request, hosts[0] if hosts else None, count=count, from_date=from_date,
                                            qfilter=qfilter, dict_format=False)

    def get_field_stats_table(self, request, field, FieldTable, hosts=None, key='host',
                              count=20, from_date=0, qfilter=None, raw=False):
        if raw:
            # This is some weird elastic stuff
            field += '.' + settings.ELASTICSEARCH_KEYWORD
        return es_graphs.es_get_field_stats_as_table(request, field, FieldTable, hosts[0] if hosts else None, key=key,
                                                     count=count, from_date=from_date, qfilter=qfilter)

    def get_field_stats_dict(self, request, field, hosts=None, key='host',
                             count=20, from_date=0, qfilter=None, raw=False):
        if raw:
            field += '.' + settings.ELASTICSEARCH_KEYWORD
        return es_graphs.es_get_field_stats(request, field, hosts[0] if hosts else None, key=key, count=count,
                                            from_date=from_date, qfilter=qfilter)

    def get_alerts_count(self, from_date=0, hosts=None, qfilter=None, prev=0):
        return es_graphs.es_get_alerts_count(from_date=from_date, hosts=hosts, qfilter=qfilter,
                                             prev=prev)

    def get_timeline(from_date=0, interval=None, hosts = None, qfilter = None, tags=False):
        return es_graphs.es_get_timeline(from_date=from_date, interval=interval, hosts=hosts,
                                         qfilter=qfilter, tags=tags)

    def get_rules_per_category(self, from_date=0, hosts = None, qfilter = None):
        return es_graphs.es_get_rules_per_category(from_data=from_date, hosts=hosts, qfilter=qfilter)

    def get_sid_by_hosts(self, request, sid, count=20, from_date=0, dict_format=False):
        return es_graphs.es_get_sid_by_hosts(request, sid, count, from_date, dict_format)

    def get_top_rules(self, request, hostname, count=20, from_date=0, order='desc', interval=None, qfilter=None):
        return es_graphs.es_get_top_rules(request, hostname, count, from_date, order, interval, qfilter)

    def es_get_sid_by_hosts(self, request, sid, count=20, from_date=0, dict_format=False):
        return es_graphs.es_get_sid_by_hosts(request, sid=sid, count=count,
                                             from_date=from_date, dict_format=dict_format)

    def get_sid_by_hosts_dict(self, request, sid, count=20, from_date=0):
        return es_graphs.es_get_sid_by_hosts(request, sid=sid, count=count,
                                             from_date=from_date, dict_format=True)

    def get_sid_by_hosts_table(self, request, sid, count=20, from_date=0):
        return es_graphs.es_get_sid_by_hosts(request, sid=sid, count=count,
                                             from_date=from_date, dict_format=False)

    def get_es_major_version(self):
        return es_graphs.get_es_major_version()

    # NOTE: There are several es_* functions that are not implemented.
