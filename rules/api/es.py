import time
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from drf_spectacular.utils import extend_schema
from elasticsearch.exceptions import ConnectionError
from rest_framework import exceptions, serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from rules.es_analytics import (
    ESFieldUniqAgg,
    ESGenericSearch,
    ESGetUniqueFields,
    ESGraphAgg,
)
from rules.es_data import ESData
from rules.es_graphs import (
    ESAlertsCount,
    ESAlertsTrend,
    ESError,
    ESEventsFromFlowID,
    ESEventsTail,
    ESEventsTimeline,
    ESFieldsStats,
    ESFieldStats,
    ESFlowTimeline,
    ESHealth,
    ESIPFlowTimeline,
    ESIppairAlerts,
    ESIppairNetworkAlerts,
    ESLatestStats,
    ESMapping,
    ESMetricsTimeline,
    ESPoststats,
    ESRulesPerCategory,
    ESRulesStats,
    ESShardStats,
    ESSidByHosts,
    ESSigsListHits,
    ESStats,
    ESSuriLogTail,
    ESTimeline,
    ESTimeRangeAllAlerts,
    ESTopRules,
)
from rules.es_query import ESPaginator, build_es_url
from scirius.rest_utils import (
    ESManageMultipleESIndexesViewSet,
)
from scirius.utils import get_middleware_module

Probe = __import__(settings.RULESET_MIDDLEWARE)


@extend_schema(tags=["ES"])
class ESBaseViewSet(APIView):
    """
    ES Abstract Base class
    """

    def get(self, request, format=None):
        try:
            return self._get(request, format)
        except ESError as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _get(self, request, format):
        raise NotImplementedError("This is an abstract class. ES sub classes must override this method")


@extend_schema(tags=["ES", "Rule"])
class ESRulesViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show rules stats:\n
        curl -k https://x.x.x.x/rest/rules/es/rules/?hosts=ProbeMain&from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET
        curl -k https://x.x.x.x/rest/rules/es/rules/?hosts=ProbeMain&from_date=1537264545477&qfilter=<"filter in Elasticsearch Query String Query format"> -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"rules":[{"key":2522690,"doc_count":5},{"key":2100498,"doc_count":4},{"key":2523038,"doc_count":3},{"key":2013028,"doc_count":2},{"key":2522628,"doc_count":1},{"key":2522916,"doc_count":1}]}

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.configuration_view", "rules.events_view"),
    }

    def _get(self, request, format=None):
        errors = {}
        if "hosts" not in request.GET:
            errors["hosts"] = ["This field is required."]

        if len(errors) > 0:
            raise serializers.ValidationError(errors)

        return Response({"rules": ESRulesStats(request).get(dict_format=True)})


@extend_schema(tags=["ES", "Rule"])
class ESRuleViewSet(ESBaseViewSet, ESManageMultipleESIndexesViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show a rule stats:\n
        curl -k https://x.x.x.x/rest/rules/es/rule/?sid=2522628&from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"rule":[{"key":"ProbeMain","doc_count":1}]}

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.configuration_view", "rules.events_view"),
    }

    def _get(self, request, format=None):
        sid = request.GET.get("sid", None)

        errors = {}
        if sid is None:
            errors["sid"] = ["This field is required."]

        if len(errors) > 0:
            raise serializers.ValidationError(errors)

        return Response({"rule": ESSidByHosts(request, view=self).get(sid, dict_format=True)})


@extend_schema(tags=["ES", "Rule"])
class ESTopRulesViewSet(ESBaseViewSet, ESManageMultipleESIndexesViewSet):
    """ """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        count = request.GET.get("count", 20)
        order = request.GET.get("order", "desc")

        if "hosts" not in request.GET:
            errors = {"hosts": ["This field is required."]}
            raise serializers.ValidationError(errors)

        return Response(ESTopRules(request, view=self).get(count=count, order=order))


class ESSigsListViewSet(ESBaseViewSet, ESManageMultipleESIndexesViewSet):
    """ """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        sids = request.GET.get("sids", None)

        errors = {}
        if sids is None:
            errors["sids"] = ["This field is required."]

        if "hosts" not in request.GET:
            errors["hosts"] = ["This field is required."]

        if len(errors) > 0:
            raise serializers.ValidationError(errors)

        return Response(ESSigsListHits(request, view=self).get(sids))


class ESPostStatsViewSet(ESBaseViewSet):
    """ """

    REQUIRED_GROUPS = {
        "READ": ("rules.ruleset_policy_view",),
    }

    def _get(self, request, format=None):
        value = request.GET.get("value", None)
        return Response(ESPoststats(request).get(value=value))


class _ESFieldsNoKeyword:
    NO_KEYWORD_FIELDS = (
        "src_port",
        "dest_port",
        "alert.signature_id",
        "alert.severity",
        "http.length",
        "http.status",
        "vlan",
        "geoip.provider.autonomous_system_number",
        "tunnel.depth",
        "flow.dest_port",
        "flow.src_port",
        "stamus.incidents_id",
        "stamus.asset_info.incident_id",
        "stamus.offender_info.incident_id",
    )


class ESFieldsStatsViewSet(ESBaseViewSet, ESManageMultipleESIndexesViewSet, _ESFieldsNoKeyword):
    """ """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        errors = {}
        fields = request.GET.get("fields", None)
        sid = request.GET.get("sid", None)

        if fields is None:
            errors = {"fields": ["This field is required."]}
            raise serializers.ValidationError(errors)

        count = request.GET.get("page_size", 10)

        field_list = fields.split(",")
        tmpl_fields = []
        for field in field_list:
            # fields starting with - are ascending ordered
            if field in self.NO_KEYWORD_FIELDS or (field[0] == '-' and field[1:] in self.NO_KEYWORD_FIELDS):
                tmpl_fields.append({'name': field, 'key': field})
            else:
                tmpl_fields.append({'name': field, 'key': field + '.' + settings.ELASTICSEARCH_KEYWORD})

        values = ESFieldsStats(request, view=self).get(sid, tmpl_fields, count=count, dict_format=True)

        return Response(values)


class ESFieldStatsViewSet(ESBaseViewSet, ESManageMultipleESIndexesViewSet, _ESFieldsNoKeyword):
    """ """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        errors = {}
        field = request.GET.get("field", None)
        sid = request.GET.get("sid", None)
        ordering = request.GET.get("ordering", "desc")

        if ordering not in ("asc", "desc"):
            raise serializers.ValidationError({"ordering": ['Wrong value, "asc" or "desc" must be used']})

        if field is None:
            errors = {"field": ["This field is required."]}
            raise serializers.ValidationError(errors)

        filter_ip = request.GET.get("field", "src_ip")
        count = request.GET.get("page_size", 10)

        if filter_ip not in self.NO_KEYWORD_FIELDS:
            filter_ip = filter_ip + "." + settings.ELASTICSEARCH_KEYWORD

        hosts = ESFieldStats(request, view=self).get(sid, filter_ip, count=count, ordering=ordering, dict_format=True)

        return Response(hosts)


class ESFilterIPViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"
    field: rule_src, rule_dest, rule_source, rule_target
           rule_src / rule_dest: src & dest IP of the packet that triggered the alert
           rule_source / rule_target: IP of the source & target of the attack

    Show a rule stats:\n
        curl -k https://x.x.x.x/rest/rules/es/filter_ip/?field=rule_src&sid=2522628&from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        [{"key":"212.47.239.163","doc_count":1}]

    Show a rule stats:\n
        curl -k https://x.x.x.x/rest/rules/es/filter_ip/?field=rule_dest&sid=2522628&from_date=1537264545477 -H 'Authorization: Token dba92b07973ba061f9a0d48a1afd98d1e7b717d6' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        [{"key":"192.168.0.14","doc_count":1}]

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    RULE_FIELDS_MAPPING = {
        "rule_src": "src_ip",
        "rule_dest": "dest_ip",
        "rule_source": "alert.source.ip",
        "rule_target": "alert.target.ip",
    }

    def _get(self, request, format=None):
        errors = {}
        field = request.GET.get("field", None)
        sid = request.GET.get("sid", None)

        if field is None:
            errors["field"] = ["This field is required."]
            raise serializers.ValidationError(errors)

        if field not in list(self.RULE_FIELDS_MAPPING.keys()):
            raise exceptions.NotFound(detail='"%s" is not a valid field' % field)

        filter_ip = self.RULE_FIELDS_MAPPING[field]
        count = request.GET.get("page_size", 10)

        hosts = ESFieldStats(request).get(
            sid, filter_ip + "." + settings.ELASTICSEARCH_KEYWORD, count=count, dict_format=True
        )

        return Response(hosts)


class ESTimelineViewSet(ESBaseViewSet, ESManageMultipleESIndexesViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show timeline:\n
        curl -k https://x.x.x.x/rest/rules/es/timeline/?hosts=ProbeMain&from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET
        curl -k https://x.x.x.x/rest/rules/es/timeline/?hosts=ProbeMain&from_date=1537264545477&qfilter=<"filter in Elasticsearch Query String Query format"> -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
       HTTP/1.1 200 OK
       {"ProbeMain":{"entries":[{"count":2,"time":1530620640000},{"count":17,"time":1530698400000},{"count":1,"time":1530750240000}]},"from_date":1528184544572,"interval":25920000}

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view", "rules.configuration_view"),
    }
    no_tenant_check = True

    def _get(self, request, format=None):
        tags = False if request.GET.get("target", "false") == "false" else True
        return Response(ESTimeline(request, view=self).get(tags=tags))


class ESLogstashEveViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Logstash Events examples:\n
        1. curl -k "https://x.x.x.x/rest/rules/es/logstash_eve/?value=system.cpu.user.pct&from_date=1540211796478&hosts=stamus"  -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET
        2. curl -k https://x.x.x.x/rest/rules/es/logstash_eve/?value=system.memory.actual.used.pct&from_date=1537264545477&hosts=ProbeMain -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET
        3. curl -k https://x.x.x.x/rest/rules/es/logstash_eve/?value=system.network.in.bytes&from_date=1537264545477&hosts=ProbeMain&qfilter=system.network.name:eth0 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET
        4. curl -k https://x.x.x.x/rest/rules/es/logstash_eve/?value=system.filesystem.used.pct&from_date=1537264545477&hosts=ProbeMain&qfilter=system.filesystem.mount_point.raw:/var/lib/lxc/elasticsearch/rootfs/var/lib/elasticsearch -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET
        5. curl -k "https://x.x.x.x/rest/rules/es/logstash_eve/?value=system.filesystem.used.pct&from_date=1540210439302&hosts=stamus&qfilter=system.filesystem.mount_point.raw:\"/var/lib/lxc/elasticsearch/rootfs/var/lib/elasticsearch\"" -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        1. {"from_date":1540211796478,"interval":868000,"stamus":{"entries":[{"mean":0.2518125013448298,"time":1540213664000},{"mean":0.12792068951088806,"time":1540214532000},{"mean":0.2473448278575108,"time":1540215400000},
           {"mean":0.17718275841967812,"time":1540216268000},{"mean":0.26032413490887346,"time":1540217136000},{"mean":0.12027241340998945,"time":1540218004000},{"mean":0.11639655150216201,"time":1540218872000},
           {"mean":0.22578214348426887,"time":1540219740000},{"mean":0.2087103447009777,"time":1540220608000},{"mean":0.18898275957025332,"time":1540221476000},{"mean":0.33865516992478534,"time":1540222344000},
           {"mean":0.2423620681310522,"time":1540223212000},{"mean":0.15318965500798717,"time":1540224080000},{"mean":0.15162413772837868,"time":1540224948000},{"mean":0.25527407394515145,"time":1540225816000},
           {"mean":null,"time":1540226684000},{"mean":null,"time":1540227552000},{"mean":null,"time":1540228420000},{"mean":null,"time":1540229288000},{"mean":null,"time":1540230156000},{"mean":null,"time":1540231024000},
           {"mean":null,"time":1540231892000},{"mean":null,"time":1540232760000},{"mean":null,"time":1540233628000},{"mean":null,"time":1540234496000},{"mean":null,"time":1540235364000},{"mean":null,"time":1540236232000},
           {"mean":null,"time":1540237100000},{"mean":null,"time":1540237968000},{"mean":null,"time":1540238836000},{"mean":null,"time":1540239704000},{"mean":null,"time":1540240572000},{"mean":null,"time":1540241440000},
           {"mean":null,"time":1540242308000},{"mean":null,"time":1540243176000},{"mean":null,"time":1540244044000},{"mean":null,"time":1540244912000},{"mean":null,"time":1540245780000},{"mean":null,"time":1540246648000},
           {"mean":null,"time":1540247516000},{"mean":null,"time":1540248384000},{"mean":null,"time":1540249252000},{"mean":null,"time":1540250120000},{"mean":null,"time":1540250988000},{"mean":null,"time":1540251856000},
           {"mean":null,"time":1540252724000},{"mean":null,"time":1540253592000},{"mean":null,"time":1540254460000},{"mean":null,"time":1540255328000},{"mean":null,"time":1540256196000},{"mean":null,"time":1540257064000},
           {"mean":null,"time":1540257932000},{"mean":null,"time":1540258800000},{"mean":null,"time":1540259668000},{"mean":null,"time":1540260536000},{"mean":null,"time":1540261404000},{"mean":null,"time":1540262272000},
           {"mean":null,"time":1540263140000},{"mean":null,"time":1540264008000},{"mean":null,"time":1540264876000},{"mean":null,"time":1540265744000},{"mean":null,"time":1540266612000},{"mean":null,"time":1540267480000},
           {"mean":null,"time":1540268348000},{"mean":null,"time":1540269216000},{"mean":null,"time":1540270084000},{"mean":null,"time":1540270952000},{"mean":null,"time":1540271820000},{"mean":null,"time":1540272688000},
           {"mean":null,"time":1540273556000},{"mean":null,"time":1540274424000},{"mean":null,"time":1540275292000},{"mean":null,"time":1540276160000},{"mean":null,"time":1540277028000},{"mean":0.24997000135481356,"time":1540277896000},
           {"mean":0.18144138093138562,"time":1540278764000},{"mean":0.33640000134192666,"time":1540279632000},{"mean":0.2678482750880307,"time":1540280500000},{"mean":0.16719654998902617,"time":1540281368000},
           {"mean":0.3015750005309071,"time":1540282236000},{"mean":0.3708103494397525,"time":1540283104000},{"mean":0.3803034447904291,"time":1540283972000},{"mean":0.2580206908028701,"time":1540284840000},
           {"mean":0.15135862035997982,"time":1540285708000},{"mean":0.17907241320815578,"time":1540286576000},{"mean":0.19569310314696411,"time":1540287444000},{"mean":0.15246896651284447,"time":1540288312000},
           {"mean":0.1365241377518095,"time":1540289180000},{"mean":0.13442758676306954,"time":1540290048000},{"mean":0.1337482757095633,"time":1540290916000},{"mean":0.13650000069675775,"time":1540291784000},
           {"mean":0.13234137872169757,"time":1540292652000},{"mean":0.13395862050097565,"time":1540293520000},{"mean":0.1352275856610002,"time":1540294388000},{"mean":0.1356607140707118,"time":1540295256000},
           {"mean":0.2512724152926741,"time":1540296124000},{"mean":0.2668586211471722,"time":1540296992000},{"mean":0.17512963049941593,"time":1540297860000}]}}

        2. {"ProbeMain":{"entries":[{"mean":0.3259543928641156,"time":1530620640000},{"mean":null,"time":1530646560000},{"mean":0.1408457946136733,"time":1530672480000},{"mean":0.21490591046354307,"time":1530698400000},{"mean":null,"time":1530724320000},
           {"mean":0.3362637047414426,"time":1530750240000},{"mean":0.3794413974849127,"time":1530776160000}]},"from_date":1528189751975,"interval":25920000}

        3. {"ProbeMain":{"entries":[{"mean":279981525.3389121,"time":1530620640000},{"mean":null,"time":1530646560000},{"mean":150212918.69626167,"time":1530672480000},
           {"mean":3426892519.905911,"time":1530698400000},{"mean":null,"time":1530724320000},{"mean":155888225.38518518,"time":1530750240000},{"mean":359010903.6592179,"time":1530776160000}]},"from_date":1528189528880,"interval":25920000}

        4. {"from_date":1528189589850,"interval":25920000}

        5. {"from_date":1540210439302,"interval":880000,"stamus":{"entries":[{"mean":9.999999747378752e-05,"time":1540213680000},{"mean":9.999999747378752e-05,"time":1540214560000},{"mean":9.999999747378752e-05,"time":1540215440000},
           {"mean":9.999999747378752e-05,"time":1540216320000},{"mean":9.999999747378752e-05,"time":1540217200000},{"mean":9.999999747378752e-05,"time":1540218080000},{"mean":9.999999747378752e-05,"time":1540218960000},
           {"mean":9.999999747378752e-05,"time":1540219840000},{"mean":9.999999747378752e-05,"time":1540220720000},{"mean":9.999999747378752e-05,"time":1540221600000},{"mean":9.999999747378752e-05,"time":1540222480000},
           {"mean":9.999999747378752e-05,"time":1540223360000},{"mean":9.999999747378752e-05,"time":1540224240000},{"mean":0.00010344827324874571,"time":1540225120000},{"mean":0.0001142857113986143,"time":1540226000000},
           {"mean":null,"time":1540226880000},{"mean":null,"time":1540227760000},{"mean":null,"time":1540228640000},{"mean":null,"time":1540229520000},{"mean":null,"time":1540230400000},{"mean":null,"time":1540231280000},
           {"mean":null,"time":1540232160000},{"mean":null,"time":1540233040000},{"mean":null,"time":1540233920000},{"mean":null,"time":1540234800000},{"mean":null,"time":1540235680000},{"mean":null,"time":1540236560000},
           {"mean":null,"time":1540237440000},{"mean":null,"time":1540238320000},{"mean":null,"time":1540239200000},{"mean":null,"time":1540240080000},{"mean":null,"time":1540240960000},{"mean":null,"time":1540241840000},
           {"mean":null,"time":1540242720000},{"mean":null,"time":1540243600000},{"mean":null,"time":1540244480000},{"mean":null,"time":1540245360000},{"mean":null,"time":1540246240000},{"mean":null,"time":1540247120000},
           {"mean":null,"time":1540248000000},{"mean":null,"time":1540248880000},{"mean":null,"time":1540249760000},{"mean":null,"time":1540250640000},{"mean":null,"time":1540251520000},{"mean":null,"time":1540252400000},
           {"mean":null,"time":1540253280000},{"mean":null,"time":1540254160000},{"mean":null,"time":1540255040000},{"mean":null,"time":1540255920000},{"mean":null,"time":1540256800000},{"mean":null,"time":1540257680000},
           {"mean":null,"time":1540258560000},{"mean":null,"time":1540259440000},{"mean":null,"time":1540260320000},{"mean":null,"time":1540261200000},{"mean":null,"time":1540262080000},{"mean":null,"time":1540262960000},
           {"mean":null,"time":1540263840000},{"mean":null,"time":1540264720000},{"mean":null,"time":1540265600000},{"mean":null,"time":1540266480000},{"mean":null,"time":1540267360000},{"mean":null,"time":1540268240000},
           {"mean":null,"time":1540269120000},{"mean":null,"time":1540270000000},{"mean":null,"time":1540270880000},{"mean":null,"time":1540271760000},{"mean":null,"time":1540272640000},{"mean":null,"time":1540273520000},
           {"mean":null,"time":1540274400000},{"mean":null,"time":1540275280000},{"mean":null,"time":1540276160000},{"mean":null,"time":1540277040000},{"mean":9.999999747378752e-05,"time":1540277920000},
           {"mean":9.999999747378752e-05,"time":1540278800000},{"mean":9.999999747378752e-05,"time":1540279680000},{"mean":9.999999747378752e-05,"time":1540280560000},{"mean":9.999999747378752e-05,"time":1540281440000},
           {"mean":9.999999747378752e-05,"time":1540282320000},{"mean":9.999999747378752e-05,"time":1540283200000},{"mean":9.999999747378752e-05,"time":1540284080000},{"mean":0.00010666666397204001,"time":1540284960000},
           {"mean":0.00011034482479866208,"time":1540285840000},{"mean":0.00013103447944841124,"time":1540286720000},{"mean":0.00019333332844932252,"time":1540287600000},{"mean":0.00019999999494757503,"time":1540288480000},
           {"mean":0.00019999999494757503,"time":1540289360000},{"mean":0.00019999999494757503,"time":1540290240000},{"mean":0.00019999999494757503,"time":1540291120000},{"mean":0.00019999999494757503,"time":1540292000000},
           {"mean":0.00019999999494757503,"time":1540292880000},{"mean":0.00019999999494757503,"time":1540293760000},{"mean":0.00019999999494757503,"time":1540294640000},{"mean":0.00019999999494757503,"time":1540295520000},
           {"mean":0.00019999999494757503,"time":1540296400000},{"mean":0.00019999999494757503,"time":1540297280000},{"mean":0.00019999999494757503,"time":1540298160000}]}}

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.configuration_view",),
    }

    def _get(self, request, format=None):
        value = request.GET.get("value", "eve.total.rate_1m")
        hosts = self.request.GET.get("hosts", "global")
        hosts = hosts.split(",")

        res = {}
        for host in hosts:
            data = ESMetricsTimeline(request, value).get(host=host)
            res.update(data)

        return Response(res)


class ESHealthViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show health:\n
        curl -k https://x.x.x.x/rest/rules/es/health/ -H 'Authorization: Token dba92b07973ba061f9a0d48a1afd98d1e7b717d6' -H 'Content-Type: application/json' -X GET

    Return:\n
        {"status":"green","number_of_nodes":1,"unassigned_shards":0,"number_of_pending_tasks":0,"number_of_in_flight_fetch":0,"timed_out":false,"active_primary_shards":90,"task_max_waiting_in_queue_millis":0,
        "cluster_name":"elasticsearch","relocating_shards":0,"active_shards_percent_as_number":100.0,"active_shards":90,"initializing_shards":0,"number_of_data_nodes":1,"delayed_unassigned_shards":0}

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.configuration_view",),
    }
    no_tenant_check = True

    def _get(self, request, format=None):
        return Response(ESHealth(request).get())


class ESStatsViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show stats:\n
        curl -k https://x.x.x.x/rest/rules/es/stats/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        {"status":"green","cluster_name":"elasticsearch","timestamp":1530781977351,"_nodes":{"successful":1,"failed":0,"total":1},
        "indices":{"count":18,"completion":{"size_in_bytes":0},"fielddata":{"evictions":0,"memory_size_in_bytes":6800},"docs":{"count":94039,"deleted":0},
        "segments":{"count":367,"max_unsafe_auto_id_timestamp":9223372036854775807,"term_vectors_memory_in_bytes":0,"version_map_memory_in_bytes":4283,
        "norms_memory_in_bytes":12608,"stored_fields_memory_in_bytes":127544,"file_sizes":{},"doc_values_memory_in_bytes":1683116,"fixed_bit_set_memory_in_bytes":0,
        "points_memory_in_bytes":42600,"terms_memory_in_bytes":6025236,"memory_in_bytes":7891104,"index_writer_memory_in_bytes":38890804},
        "shards":{"replication":0.0,"total":90,"primaries":90,"index":{"replication":{"max":0.0,"avg":0.0,"min":0.0},"primaries":{"max":5,"avg":5.0,"min":5},
        "shards":{"max":5,"avg":5.0,"min":5}}},"query_cache":{"miss_count":409,"total_count":2352,"evictions":0,"memory_size_in_bytes":62169,"hit_count":1943,
        "cache_size":44,"cache_count":44},"store":{"size_in_bytes":90624330,"throttle_time_in_millis":0}},"nodes":{"count":{"master":1,"total":1,"data":1,
        "coordinating_only":0,"ingest":1},"fs":{"free_in_bytes":1081936871424,"spins":"true","total_in_bytes":1082123276288,"available_in_bytes":1070925000704},
        "versions":["5.6.9"],"process":{"open_file_descriptors":{"max":394,"avg":394,"min":394},"cpu":{"percent":0}},"network_types":{"transport_types":{"netty4":1},
        "http_types":{"netty4":1}},"jvm":{"mem":{"heap_used_in_bytes":1564867136,"heap_max_in_bytes":3119906816},"threads":39,"max_uptime_in_millis":9822316,
        "versions":[{"vm_name":"OpenJDK 64-Bit Server VM","count":1,"version":"1.8.0_171","vm_version":"25.171-b11","vm_vendor":"Oracle Corporation"}]},"plugins":[],
        "os":{"mem":{"free_in_bytes":607629312,"free_percent":10,"used_in_bytes":5666541568,"total_in_bytes":6274170880,"used_percent":90},"allocated_processors":2,
        "names":[{"count":1,"name":"Linux"}],"available_processors":2}}}}

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.configuration_view",),
    }

    def _get(self, request, format=None):
        return Response(ESStats(request).get())


class ESShardStatsViewSet(ESBaseViewSet):
    REQUIRED_GROUPS = {
        "READ": ("rules.configuration_view",),
    }

    def _get(self, request, format=None):
        return Response(ESShardStats(request).get())


@extend_schema(tags=["ES"])
class ESCheckVersionViewSet(APIView):
    """ """

    REQUIRED_GROUPS = {
        "WRITE": ("rules.configuration_view",),
    }

    def post(self, request, format=None):
        res = {}
        try:
            es_url = self.request.data.get("es_url", "")
            es_user = self.request.data.get("es_user", "")
            es_pass = self.request.data.get("es_pass", "")

            es_url = build_es_url(es_url, es_user, es_pass)
            res = get_middleware_module("common").check_es_version(request, es_url)
        except (ValueError, ValidationError) as error:
            res["error"] = "Invalid hostname or IP, %s" % error
        return Response(res)


@extend_schema(tags=["ES", "Rule", "Source"])
class ESRulesPerCategoryViewSet(ESBaseViewSet, ESManageMultipleESIndexesViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show rules per category:\n
        curl -k https://x.x.x.x/rest/rules/es/rules_per_category/?hosts=ProbeMain&from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET
        curl -k https://x.x.x.x/rest/rules/es/rules_per_category/?hosts=ProbeMain&from_date=1537264545477&qfilter=<"filter in Elasticsearch Query String Query format"> -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"children":[{"children":[{"msg":"ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 520","key":2523038,"doc_count":17},
        {"msg":"ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 434","key":2522866,"doc_count":14},
        {"msg":"ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 346","key":2522690,"doc_count":13},
        {"msg":"ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 315","key":2522628,"doc_count":1},
        {"msg":"ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 459","key":2522916,"doc_count":1}],
        "key":"Misc Attack","doc_count":46},{"children":[{"msg":"GPL ATTACK_RESPONSE id check returned root","key":2100498,"doc_count":4}],
        "key":"Potentially Bad Traffic","doc_count":4},{"children":[{"msg":"ET POLICY curl User-Agent Outbound","key":2013028,"doc_count":2}],
        "key":"Attempted Information Leak","doc_count":2}],"key":"categories"}

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.ruleset_policy_view",),
    }

    def _get(self, request, format=None):
        return Response(ESRulesPerCategory(request, view=self).get())


@extend_schema(tags=["ES", "Alert"])
class ESAlertsCountViewSet(ESBaseViewSet, ESManageMultipleESIndexesViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show alerts count:\n
        1. curl -k https://x.x.x.x/rest/rules/es/alerts_count/?hosts=ProbeMain&from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET
        2. curl -k https://x.x.x.x/rest/rules/es/alerts_count/?hosts=ProbeMain&from_date=1537264545477&prev=true -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET
        3. curl -k https://x.x.x.x/rest/rules/es/alerts_count/?hosts=ProbeMain&from_date=1537264545477&prev=true&qfilter=<"filter in Elasticsearch Query String Query format"> -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        1. {"doc_count":18}
        2. {"prev_doc_count":25,"doc_count":17}

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view", "rules.configuration_view"),
    }
    no_tenant_check = True

    def _get(self, request, format=None):
        if request.GET.get("prev") != "false":
            data = ESAlertsTrend(request, view=self).get()
        else:
            data = ESAlertsCount(request, view=self).get()
        return Response(data)


@extend_schema(tags=["ES", "Alert"])
class ESTimeRangeAllAlertsViewSet(ESBaseViewSet, ESManageMultipleESIndexesViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show alerts count:\n
        1. curl -k https://x.x.x.x/rest/rules/es/alerts_timerange/?hosts=ProbeMain -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET
        2. curl -k https://x.x.x.x/rest/rules/es/alerts_timerange/?hosts=ProbeMain&from_date=1537264545477&prev=true -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET
        3. curl -k https://x.x.x.x/rest/rules/es/alerts_timerange/?hosts=ProbeMain&from_date=1537264545477&prev=true&qfilter=<"filter in Elasticsearch Query String Query format"> -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        1. {"min_timestamp":1623685733514.0,"max_timestamp":1623686992004.0}
        2. {"min_timestamp":1623685733514.0,"max_timestamp":1623686992004.0}
        3. {"min_timestamp":1623685733514.0,"max_timestamp":1623686992004.0}

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        data = ESTimeRangeAllAlerts(request, view=self).get()
        # ceil to 1 sec while we can loose alerts if not celing
        # timestamp has been truncated by frontend
        data["max_timestamp"] = data["max_timestamp"] + 1000
        return Response(data)


class ESLatestStatsViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show alerts count:\n
        curl -k https://192.168.0.17/rest/rules/es/latest_stats/?hosts=ProbeMain&from_date=1537264545477 -H 'Authorization: Token dba92b07973ba061f9a0d48a1afd98d1e7b717d6' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"stats":{"ftp":{"memcap":0,"memcap_delta":0,"memuse":0,"memuse_delta":0},"uptime":52161,"detect":{"alert_delta":0,"engines":[{"rules_loaded":20843,"id":0,"rules_failed":0,
        "last_reload":"2018-07-11T09:45:33.630288+0200"}],"alert":65},"http":{"memcap":0,"memcap_delta":0,"memuse":0,"memuse_delta":0},
        "flow_mgr":{"rows_checked_delta":0,"rows_skipped":65534,"closed_pruned_delta":0,"rows_maxlen_delta":1,"flows_notimeout":2,"rows_empty_delta":-1,"flows_removed":0,"est_pruned":6375,
        "flows_removed_delta":0,"flows_timeout_inuse":0,"est_pruned_delta":0,"rows_busy":0,"flows_timeout":0,"new_pruned":18776,"bypassed_pruned_delta":0,"flows_checked_delta":2,"rows_skipped_delta":-1,
        "rows_maxlen":1,"new_pruned_delta":2,"rows_empty":0,"rows_busy_delta":0,"flows_notimeout_delta":2,"closed_pruned":3909,"flows_timeout_inuse_delta":0,"bypassed_pruned":0,"flows_timeout_delta":0,
        "flows_checked":2,"rows_checked":65536},"capture":{"kernel_drops_delta":0,"kernel_packets":4705396,"kernel_drops":2519,"kernel_packets_delta":517},"defrag":{"max_frag_hits":0,
        "ipv4":{"timeouts":0,"reassembled":50,"fragments_delta":0,"reassembled_delta":0,"fragments":100,"timeouts_delta":0},"max_frag_hits_delta":0,"ipv6":{"timeouts":0,"reassembled":0,"fragments_delta":0,
        "reassembled_delta":0,"fragments":0,"timeouts_delta":0}},"flow":{"tcp_delta":1,"emerg_mode_entered_delta":0,"memuse":7323352,"icmpv4_delta":0,"pkts_bypassed_delta":0,"tcp_reuse":0,
        "emerg_mode_over":0,"emerg_mode_entered":0,"udp_delta":0,"spare_delta":0,"udp":9596,"memcap":0,"icmpv6_delta":0,"tcp_reuse_delta":0,"tcp":19447,"pkts_bypassed":0,"memcap_delta":0,"icmpv6":46,
        "icmpv4":0,"memuse_delta":312,"spare":10000,"emerg_mode_over_delta":0},"tcp":{"overlap_delta":0,
        ........

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.configuration_view",),
    }

    def _get(self, request, format=None):
        return Response(ESLatestStats(request).get())


@extend_schema(tags=["ES", "Alert"])
class ESIPPairAlertsViewSet(ESBaseViewSet, ESManageMultipleESIndexesViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show ip pair alerts:\n
        curl -k https://x.x.x.x/rest/rules/es/ip_pair_alerts/?hosts=ProbeMain&from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET
        curl -k https://x.x.x.x/rest/rules/es/ip_pair_alerts/?hosts=ProbeMain&from_date=1537264545477&qfilter=<"filter in Elasticsearch Query String Query format"> -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"nodes":[{"group":4,"id":"212.47.239.163"},{"group":4,"id":"192.168.0.14"},{"group":4,"id":"37.187.17.67"},
        {"group":4,"id":"192.168.0.25"},{"group":4,"id":"62.210.244.146"}],"links":[{"source":0,"alerts":[{"key":"ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 346","doc_count":4}],
        "target":1,"value":4.772588722239782},{"source":2,"alerts":[{"key":"ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 434","doc_count":4}],
        "target":3,"value":4.772588722239782},{"source":4,"alerts":[{"key":"ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 520","doc_count":4}],
        "target":3,"value":4.772588722239782}]}

    =============================================================================================================================================================

    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        return Response(ESIppairAlerts(request, view=self).get())


@extend_schema(tags=["ES", "Alert"])
class ESIPPairNetworkAlertsViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show ip pair network alerts:\n
        curl -k https://x.x.x.x/rest/rules/es/ip_pair_network_alerts/?hosts=ProbeMain&from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"nodes":[],"links":[]}

    =============================================================================================================================================================

    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        return Response(ESIppairNetworkAlerts(request).get())


@extend_schema(tags=["ES", "Alert"])
class ESAlertsTailViewSet(ESBaseViewSet, ESManageMultipleESIndexesViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show alert tail:\n
        curl -k https://x.x.x.x/rest/rules/es/alerts_tail/?from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        []

    =============================================================================================================================================================

    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        pagination = ESPaginator(request)
        es_params = pagination.get_es_params(self)
        ordering = request.query_params.get("ordering", None)

        if not pagination.validate_ordering(ordering):
            return Response("Wrong ordering value: %s" % ordering, status=status.HTTP_400_BAD_REQUEST)

        data = ESEventsTail(request, None, view=self).get(es_params=es_params, ordering=ordering is not None)
        res = pagination.get_paginated(data)
        return Response(res)


@extend_schema(tags=["ES", "Event"])
class ESEventsTailViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show events tail:\n
        curl -k https://x.x.x.x/rest/rules/es/events_tail/?from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        []

    =============================================================================================================================================================

    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        pagination = ESPaginator(request)
        es_params = pagination.get_es_params(self)
        ordering = request.query_params.get("ordering", None)

        if not pagination.validate_ordering(ordering):
            return Response("Wrong ordering value: %s" % ordering, status=status.HTTP_400_BAD_REQUEST)

        index = settings.ELASTICSEARCH_LOGSTASH_INDEX + "*"
        data = ESEventsTail(request, index).get(es_params=es_params, ordering=ordering is not None, event_type=None)
        res = pagination.get_paginated(data)
        return Response(res)


class ESTLSTailViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show TLS tail:\n
        curl -k https://x.x.x.x/rest/rules/es/tls_tail/?from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        []

    =============================================================================================================================================================

    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        pagination = ESPaginator(request)
        es_params = pagination.get_es_params(self)
        ordering = request.query_params.get("ordering", None)

        if not pagination.validate_ordering(ordering):
            return Response("Wrong ordering value: %s" % ordering, status=status.HTTP_400_BAD_REQUEST)

        index = settings.ELASTICSEARCH_LOGSTASH_INDEX + "tls-*"
        data = ESEventsTail(request, index).get(es_params=es_params, ordering=ordering is not None, event_type="tls")
        return pagination.get_paginated_response(data)


class ESFlowTimelineViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show flow timeline:\n
        curl -k https://x.x.x.x/rest/rules/es/flow_timeline/?from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        []

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        return Response(ESFlowTimeline(request).get())


class ESIPFlowTimelineViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show flow timeline:\n
        curl -v -k https://x.x.x.x/rest/rules/es/flow_timeline_src_dest/?start_date=1655279226&end_date=1655365626&ip=10.7.5.5 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"took":5,"timed_out":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},"hits":{"total":{"value":33,"relation":"eq"},"max_score":null,"hits":[]},"aggregations":{"date":{"buckets":[{"key_as_string":"2022-06-15T07:41:36.480Z","key":1655278896480,"doc_count":0,"rx_bytes":{"value":0.0},"tx_bytes":{"value":0.0}},{"key_as_string":"2022-06-15T08:00:00.000Z","key":1655280000000,"doc_count":33,"rx_bytes":{"value":8010170.0},"tx_bytes":{"value":0.0}},{"key_as_string":"2022-06-15T08:18:23.520Z","key":1655281103520,"doc_count":0,"rx_bytes":{"value":0.0},"tx_bytes":{"value":0.0}}, ...]}}}

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        ip = request.GET.get("ip", None)
        if ip is None:
            raise serializers.ValidationError({"ip": ["This field is required"]})

        src_ip_res = ESIPFlowTimeline(request).get(target="src_ip", ip=ip)
        dest_ip_res = ESIPFlowTimeline(request).get(target="dest_ip", ip=ip)

        for idx, item in enumerate(src_ip_res.get("aggregations", {}).get("date", {}).get("buckets", [])):
            item.pop("doc_count")
            item["rx_bytes"]["value"] += dest_ip_res["aggregations"]["date"]["buckets"][idx]["tx_bytes"]["value"]
            item["tx_bytes"]["value"] += dest_ip_res["aggregations"]["date"]["buckets"][idx]["rx_bytes"]["value"]

        return Response(src_ip_res)


@extend_schema(tags=["ES", "Event"])
class ESEventsTimelineViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    qfilter: "filter in Elasticsearch Query String Query format"

    Show events timeline:\n
        curl -k https://x.x.x.x/rest/rules/es/events_timeline/?from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        []

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        return Response(ESEventsTimeline(request).get())


@extend_schema(tags=["ES", "Event"])
class ESEventsFromFlowIDViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show events from an alert.flow_id:\n
        curl -k https://x.x.x.x/rest/rules/es/events_from_flow_id/?from_date=1537264545477&qfilter=flow_id:1259054449405574 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        []

    =============================================================================================================================================================

    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None):
        return Response(ESEventsFromFlowID(request).get())


class ESSuriLogTailViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show alert tail:\n
        curl -k https://192.168.0.17/rest/rules/es/suri_log_tail/?hosts=ProbeMain&from_date=1537264545477 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        [{"sort":[1530779257071],"_type":"log","_source":{"engine":{"message":"This is Suricata version 4.1.0-dev (rev 2973ecd)"},"type":"log","event_type":"engine","timestamp":"2018-07-05T10:27:37.071716+0200","tags":["beats_input_codec_json_applied"],"beat":{"hostname":"ProbeMain","name":"ProbeMain","version":"5.6.9"},"input_type":"log","@timestamp":"2018-07-05T08:27:37.071Z","source":"/var/log/suricata/suricata.json","host":"ProbeMain","offset":56988,"@version":"1"},"_score":null,"_index":"logstash-2018.07.05","_id":"AWRpIvbZiu8Nj3hTWm5b"},
        {"sort":[1530779257229],"_type":"log","_source":{"engine":{"message":"CPUs/cores online: 1"},"type":"log","event_type":"engine","timestamp":"2018-07-05T10:27:37.229985+0200","tags":["beats_input_codec_json_applied"],"beat":{"hostname":"ProbeMain","name":"ProbeMain","version":"5.6.9"},"input_type":"log","@timestamp":"2018-07-05T08:27:37.229Z","source":"/var/log/suricata/suricata.json","host":"ProbeMain","offset":57103,"@version":"1"},"_score":null,"_index":"logstash-2018.07.05","_id":"AWRpIvbZiu8Nj3hTWm5c"},
        {"sort":[1530779257902],"_type":"log","_source":{"engine":{"message":"eve-log output device (regular) initialized: eve-alert.json"},"type":"log","event_type":"engine","timestamp":"2018-07-05T10:27:37.902961+0200","tags":["beats_input_codec_json_applied"],"beat":{"hostname":"ProbeMain","name":"ProbeMain","version":"5.6.9"},"input_type":"log","@timestamp":"2018-07-05T08:27:37.902Z","source":"/var/log/suricata/suricata.json","host":"ProbeMain","offset":57748,"@version":"1"},"_score":null,"_index":"logstash-2018.07.05","_id":"AWRpIvbZiu8Nj3hTWm5g"},
        {"sort":[1530779257902],"_type":"log","_source":{"engine":{"message":"eve-log output device (regular) initialized: eve.json"},"type":"log","event_type":"engine","timestamp":"2018-07-05T10:27:37.902882+0200","tags":["beats_input_codec_json_applied"],"beat":{"hostname":"ProbeMain","name":"ProbeMain","version":"5.6.9"},"input_type":"log","@timestamp":"2018-07-05T08:27:37.902Z","source":"/var/log/suricata/suricata.json","host":"ProbeMain","offset":57376,"@version":"1"},"_score":null,"_index":"logstash-2018.07.05","_id":"AWRpIvbZiu8Nj3hTWm5e"},
        ....
        ]

    =============================================================================================================================================================

    """

    REQUIRED_GROUPS = {
        "READ": ("rules.configuration_view",),
    }

    def _get(self, request, format=None):
        return Response(ESSuriLogTail(request).get())


class ESDeleteLogsViewSet(APIView):
    """
    =============================================================================================================================================================
    ==== POST ====\n
    Erase all elasticsearch logs:\n
        curl -k https://x.x.x.x/rest/rules/es/delete_all_logs/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"appliance_pk": <pk_appliance>}'

    Return:\n
        HTTP/1.1 204 No Content
        {"delete_es_logs":"ok"}

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "WRITE": ("rules.configuration_edit",),
    }

    def post(self, request, format=None):
        es_data = ESData()
        msg = None
        errors = None

        try:
            es_data.es_clear()
            _, errors = es_data.es_clear()
        except ConnectionError:
            msg = "Could not connect to Elasticsearch"
        except Exception as e:
            msg = "Clearing failed: %s" % e

        if msg is not None:
            raise serializers.ValidationError({"delete_es_logs": [msg]})

        res = {"delete_es_logs": "ok"}
        if errors:
            res.update({"warning": ", ".join(errors)})
        return Response(res)


class HuntFilterAPIView(APIView):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Get all hunt filters:\n
        curl -k https://x.x.x.x/rest/rules/hunt-filter/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        [{"filterType":"select","filterValues":[{"id":"untagged","title":"Untagged"},{"id":"relevant","title":"Relevant"},
        {"id":"informational","title":"Informational"}],"placeholder":"Filter hits by Tag","id":"alert.tag","title":"Tag"},
        {"filterType":"select","filterValues":[{"id":"Probe1","title":"Probe1"}],"placeholder":"Filter hits by Probe","id":"probe","title":"Probe"},
        {"placeholder":"Minimum Hits Count","title":"Alerts min","filterType":"integer","id":"hits_min","queryType":"rest"},
        {"placeholder":"Maximum Hits Count","title":"Alerts max","filterType":"integer","id":"hits_max","queryType":"rest"},
        {"placeholder":"Filter by Message","title":"Message","filterType":"text","id":"msg","queryType":"filter"},
        {"placeholder":"Filter by Content","title":"Content","filterType":"text","id":"search","queryType":"rest"},
        {"placeholder":"Filter by Signature","title":"Signature ID","filterType":"text","id":"sid","queryType":"filter"}]

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }
    no_tenant_check = True

    def get(self, request, format=None):
        filters = get_middleware_module("common").get_hunt_filters()
        return Response(filters)


class ESUniqueFieldViewSet(ESBaseViewSet):
    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format=None) -> object:
        return Response(ESGetUniqueFields(request).get(request.query_params.get("event_type", None)))


class ESFieldUniqViewSet(ESBaseViewSet):
    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _get(self, request, format) -> object:
        data = ESFieldUniqAgg(request).get()
        values = data.get("aggregations", {}).get("fields", {}).get("buckets", [])
        resp = []
        if "counts" in request.GET and request.GET["counts"] == "yes":
            resp = [{"key": b["key"], "doc_count": b["doc_count"]} for b in values]
        else:
            resp = [b["key"] for b in values]
            resp = sorted(resp)
        return Response(resp)


class ESGraphAggViewSet(ESBaseViewSet):
    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
    }

    def _fmt_simple(self, data: dict) -> dict:
        d_graph = {}
        for item in data.get("aggregations", {}).get("col_src", {}).get("buckets", []):
            if item != "":
                sub = [i["key"] for i in item["col_dest"].get("buckets", [])]
                if len(sub) > 0:
                    d_graph[item["key"]] = sub
        return d_graph

    def _fmt_networkx(self, data: dict, col_src: str, col_dest: str) -> dict:
        d_graph = {
            "nodes": [],
            "edges": [],
        }

        buckets = data.get("aggregations", {}).get("col_src", {}).get("buckets", [])
        # pass 1 - insert source nodes
        for b in buckets:
            d_graph["nodes"].append(
                {
                    "index": str(b["key"]),
                    "field": col_src,
                    "kind": "source",
                }
            )

        # pass 2 insert destination nodes
        for b in buckets:
            for b2 in b.get("col_dest", {}).get("buckets", []):
                d_graph["nodes"].append({"index": str(b2["key"]), "field": col_dest, "kind": "destination"})

        # pass 3 insert edges
        for b in buckets:
            for b2 in b.get("col_dest", {}).get("buckets", []):
                d_graph["edges"].append({"edge": [str(b["key"]), str(b2["key"])], "doc_count": b2["doc_count"]})

        return d_graph

    def _get(self, request, format=None) -> dict:
        data = ESGraphAgg(request).get()
        if len(data) == 0:
            return Response("No data", status=status.HTTP_400_BAD_REQUEST)

        col_src = request.GET.get("col_src", "src_ip")
        col_dest = request.GET.get("col_dest", "dest_ip")

        graph = self._fmt_networkx(data, col_src, col_dest)

        return Response(
            {
                "graph": graph,
            }
        )


class ESGenericSearchViewSet(ESBaseViewSet):
    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
        "WRITE": ("rules.events_view",),
    }

    def post(self, request, _=None):
        index = self.request.data.get("index")
        qfilter = self.request.data.get("qfilter")
        aggs = self.request.data.get("aggs")
        size = self.request.data.get("size")
        time_filter = self.request.data.get("time_filter", "@timestamp")

        if custom_filter := self.request.data.get("custom_filter"):
            filter = custom_filter
        else:
            now = round(time.time() * 1000)
            filter: dict[str, Any] = {
                "range": {
                    time_filter: {
                        "from": request.query_params.get("from_date", now - 86400000),  # default 24h before
                        "to": request.query_params.get("to_date", now),
                    }
                }
            }

        if not index:
            raise serializers.ValidationError({"index": ["is mandatory"]})

        if not qfilter:
            raise serializers.ValidationError({"qfilter": ["is mandatory"]})

        return Response(ESGenericSearch(request, index, qfilter, size, filter, aggs, time_filter).get())


class ESMappingViewSet(ESBaseViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Get available ES mapping. It aggregates all available indexes.

    Show rules stats:\n
        curl -k https://x.x.x.x/rest/rules/es/mapping/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {
            "@timestamp": {"type": "date"},
            // ...
            "dnp3.application.objects.variation": {"type": "long"}
        }

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        "READ": ("rules.configuration_view", "rules.events_view"),
    }

    def _get(self, request, format=None):
        return Response(ESMapping(request).get())
