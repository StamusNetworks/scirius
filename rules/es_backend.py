class ESBackend:
    """ESBackend defines the common interface for ElasticSearch like functionality.

    Currently implemented by ESClient and HumioClient.
    """
    def __init__(self):
        pass

    def get_rules_stats_table(self, request, hosts=None,
                              count=20, from_date=0, qfilter=None,
                              sort_order=None, sort_key=None):
        raise NotImplementedError()

    def get_rules_stats_dict(self, request, hosts=None,
                             count=20, from_date=0, qfilter=None,
                             sort_order=None, sort_key=None):
        raise NotImplementedError()

    def get_field_stats_table(self, request, field, FieldTable,
                              hosts=None, key='host', count=20,
                              from_date=0, qfilter=None, raw=False):
        raise NotImplementedError()

    def get_field_stats_dict(self, request, field, hosts=None,
                             key='host', count=20, from_date=0,
                             qfilter=None, raw=False):
        raise NotImplementedError()

    def get_alerts_count(self, from_date=0, hosts=None,
                         qfilter=None, prev=0):
        raise NotImplementedError()

    def get_timeline(self, from_date=0, interval=None,
                     hosts=None, qfilter=None):
        raise NotImplementedError()

    def get_rules_per_category(self, from_date=0,
                               hosts=None, qfilter=None):
        raise NotImplementedError()

    def get_top_rules(self, request, hostname, count=20, from_date=0,
                      order='desc', interval=None, qfilter=None):
        raise NotImplementedError()

    def get_sid_by_hosts(self, request, sid, count=20,
                         from_date=0, dict_format=False):
        raise NotImplementedError()

    def get_sid_by_hosts_dict(self, request, sid, count=20, from_date=0):
        raise NotImplementedError()

    def get_sid_by_hosts_table(self, request, sid, count=20, from_date=0):
        raise NotImplementedError()

    def get_es_major_version(self):
        raise NotImplementedError()

    # NOTE: There are several es_* functions that are not implemented.
