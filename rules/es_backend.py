from __future__ import unicode_literals

DEFAULT_COUNT = 20
DEFAULT_ORDER = 'desc'


class ESBackend:
    """
    ESBackend defines the common interface for ElasticSearch like functionality.
    Currently implemented by ESClient and HumioClient.
    """

    def __init__(self):
        pass

    def get_rules_stats_table(self, request, count=DEFAULT_COUNT):
        """
        Get a table of rules with their respective values.
        Contains the fields signature id, description/msg, category and hits.
        Default table implementation: :class:`tables.ExtendedRuleTable`.

        :param request: request object with get parameters
            - hosts: list of comma separated probe names (optional)
            - from_date: epoch ms of start time for alert counting
            - sort: field to sort on, e.g. '-hits' for descending on hits. (optional)
            - qfilter: query filter for the search (optional)
        :param count: number of rules in result
        :return: ordered table of rules
        """
        raise NotImplementedError()

    def get_rules_stats_dict(self, request, count=DEFAULT_COUNT):
        """
        Get a list of rules with their respective values.
        Each entry is a dict containing the fields key (signature id)
        and doc_count (number of hits).

        :param request: request object with get parameters
            - hosts: list of comma separated probe names (optional)
            - from_date: epoch ms of start time for alert counting
            - sort: field to sort on, e.g. '-hits' for descending on hits. (optional)
            - qfilter: query filter for the search (optional)
        :param count: number of rules in result
        :return: ordered list containing rule entries
        """
        raise NotImplementedError()

    def get_field_stats_table(self, request, sid, field, count=DEFAULT_COUNT):
        """
        Get a table of field values containing the number of alerts for each value of the field,
        i.e. for each field value, how many alerts had this value in this field.
        Default table implementation: :class:`tables.RuleHostTable`

        :param request: request object with get parameters
            - hosts: list of comma separated probe names (optional)
            - from_date: epoch ms of start time for alert counting
            - qfilter: query filter for the search (optional)
            - sort: field to sort on, e.g '-count' for descending on alert count (optional)
        :param sid: signature id to filter on a rule (optional).
                    If None, results from all rules are included.
        :param field: field to show the values for
        :param count: length of the resulting list
        :return: table of field values and counts
        """
        raise NotImplementedError()

    def get_field_stats_dict(self, request, sid, field, count=DEFAULT_COUNT):
        """
        Get a list of dictionary entries for values of a specific field,
        containing the number of alerts for each value of the field,
        i.e. for each field value, how many alerts had this value in this field.
        Each entry is on the form
        {'key': <field value>, 'doc_count': <alert count>}

        :param request: request object with get parameters
            - hosts: list of comma separated probe names (optional)
            - from_date: epoch ms of start time for alert counting
            - sort: field to sort on, e.g '-count' for descending on alert count (optional)
            - qfilter: query filter for the search (optional)
        :param sid: signature id to filter on a rule (optional).
                    If None, results from all rules are included.
        :param field: field to show the values for
        :param count: length of the resulting list
        :return: list containing field entries
        """
        raise NotImplementedError()

    def get_sid_by_hosts_dict(self, request, sid, count=DEFAULT_COUNT):
        """
        Given a rule, get a dictionary containing a list of probes and the respective number
        of hits for this rule on this probe.
        The dictionary is on the format
        {"rule":[{"key":"<probe>","doc_count":<alerts on rule with given sid>}]}:

        :param request: request object with get parameters
            - from_date: epoch ms of start time for alert counting
            - sort: field to sort on, e.g. '-hits' to sort on hits descending.
        :param sid: signature id of the rule
        :param count: length of the resulting list
        :return: dictionary containing a list of probes with respective hit count
        """
        raise NotImplementedError()

    def get_sid_by_hosts_table(self, request, sid, count=DEFAULT_COUNT):
        """
        Given a rule, get a table of probes and the respective number
        of hits for this rule on this probe.
        Default table implementation: :class:`tables.RuleStatsTable`

        :param request: request object with get parameters
            - from_date: epoch ms of start time for alert counting
            - sort: field to sort on, e.g. '-hits' to sort on hits descending.
        :param sid: signature id of the rule
        :param count: size of the resulting table
        :return: table over probes and hits by probe
        """
        raise NotImplementedError()

    def get_timeline(self, request, tags=False):
        """
        Get the data for a timeline of alerts, to use in the frontend.
        The timeline is a list of series (one for each probe) containing
        a list of bucket entries, each with a time (in epoch ms) and the number of
        alerts in this period.
        The result is on the form:
        {
         'from_date': <from_date epoch ms>,
         'interval': <interval ms>,
          <probe>: {entries: [{time: <bucket time epoch ms>, count: <count>}, ... ]},
          ...
        }
        :param request: request object with get parameters
            - hosts: comma separated list of probes to retrieve data for (optional)
            - from_date: start time in epoch ms (required)
            - interval: the interval size in seconds, i.e the size of each bucket (optional)
            - qfilter: query filter for the alert data (optional)
        :param tags:
        :return: dictionary data for the timeline
        """
        raise NotImplementedError()

    def get_metrics_timeline(self, request, value=None):
        """
        Get the data for a timeline of different metric data to use in the frontend.
        The result is on the form:
        {
         'from_date': <from_date epoch ms>,
         'interval': <interval ms>,
          <probe>: {entries: [
            {time: <bucket time epoch ms>, mean: <average value of metric in period>},
            ...
          ]},
          ...
        }

        :param request: request object with get parameters
            - hosts: comma separated list of probes to retrieve data for (optional)
            - from_date: start time in epoch ms (required)
            - interval: the interval size in seconds, i.e the size of each bucket (optional)
            - qfilter: query filter for the alert data (optional)
        :param value: the name of the field/value/metric to get data for (required)
        :return: dictionary data for the timeline
        """
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
        """
        Get a dict of rules with their respective alert count, by their category.
        The result is on the form:
        {
          'key': 'categories',
          'children': [
            {
              'doc_count': <alert count for rules in this category>,
              'key': <name of this category>,
              'children': [
                {'key': <sid>, 'msg': <rule msg>, 'doc_count': <rule alert count>},
                {'key': <sid>, 'msg': <rule msg>, 'doc_count': <rule alert count>},
                ...
              ]
            },
            ...
          ]
        }
        :param request: request object with get parameters
            - hosts: comma separated list of probes to retrieve data for (optional)
            - from_date: start time in epoch ms (required)
            - qfilter: query filter for the alert data (optional)
        :return:
        """
        raise NotImplementedError()

    def delete_alerts_by_sid(self, request, sid):
        raise NotImplementedError()

    def get_alerts_count(self, request, prev=0):
        """
        Get the number of alerts in the period since from_date,
        and optionally from the corresponding previous period.
        The result is a dict on the format:
        {'prev_doc_count': <previous count>, 'doc_count' <current count>}

        :param request: request object with get parameters
            - hosts: comma separated list of probes to retrieve data for (optional)
            - from_date: start time in epoch ms of the period (required)
            - qfilter: query filter for the alerts (optional)
        :param prev: get the alert count of the previous period
        :return: the alert count for the current period and the previous period
        """
        raise NotImplementedError()

    def get_latest_stats(self, request):
        raise NotImplementedError()

    def get_ippair_alerts(self, request):
        raise NotImplementedError()

    def get_ippair_network_alerts(self, request):
        raise NotImplementedError()

    def get_alerts_tail(self, request, search_target=True):
        """
        Get the raw alert json data for the last 100 alerts.
        If a query filter is set, the 100 last alerts from
        the set of filtered alerts is returned.
        The resulting list may have less than 100 entries
        if the number of alerts in the result set is less than 100.
        The result is on the format:
        [
          {'_id': 0, '_source': <raw alert json>},
          {'_id': 1, '_source': <raw alert json>},
          ...
          {'_id': 99, '_source': <raw alert json>}
        ]

        :param request: request object with get parameters
            - hosts: comma separated hosts to filter on
            - from_date: search begin date in epoch ms
            - qfilter: query filter for the search
        :param search_target:
        :return: list of the last 100 alerts
        """
        raise NotImplementedError()

    def get_suri_log_tail(self, request):
        raise NotImplementedError()

    def get_top_rules(self, request, count=DEFAULT_COUNT, order=DEFAULT_ORDER):
        """
        Get the signature ids and hits of the top n rules, ordered by hits.
        The result is on the format
        [
          {'key': <signature id>, 'doc_count': <number of hits>},
          ...
        ]
        :param request: request object with get parameters:
            - hosts: comma separated hosts to filter on
            - from_date: search begin date in epoch ms
            - qfilter: query filter for the search
        :param count: number of signatures to retrieve
        :param order: sort order for the hits (default descending)
        :return: list of signature ids and hits
        """
        raise NotImplementedError()

    def get_sigs_list_hits(self, request, sids, order=DEFAULT_ORDER):
        """
        Get the number of alerts for a list of signature ids
        The result is on the form
        [
          {'key': <signature id>, 'doc_count': <number of hits>},
          ...
        ]
        :param request: request object with get parameters:
            - hosts: comma separated hosts to filter on
            - from_date: search begin date in epoch ms
            - qfilter: query filter for the search
        :param sids: list of signature ids
        :param order: sort order, either 'desc', 'descending', 'asc' or 'ascending'
        :return: list of signature ids and hit counts
        """
        raise NotImplementedError()

    def get_es_major_version(self):
        raise NotImplementedError()

    def get_status(self):
        raise NotImplementedError()

    def get_signature_timeline_and_probe_hits(self, request, sids):
        """
        Get the total hit count, hit count by probe, and timeline data
        for alerts on the given signature ids.
        The result is on the form:
        {
          '<sid>': {
            'hits': <total alert count for sid>,
            'probes': [
              {'probe': <probe name>, 'hits': <hits on this probe>},
              ...
            ],
            'timeline_data': [
              {'date': <bucket time epoch ms>, 'hits': <alert count>},
              ...
            ]
          }
        }

        :param request: request object with get parameters:
            - from_date: from date in epoch ms
            - interval: interval size in seconds
            - qfilter: query filter for the data
        :param sids: list of signature ids to query
        :return: dictionary with hits, probe hits and timeline data
        """
        raise NotImplementedError()
