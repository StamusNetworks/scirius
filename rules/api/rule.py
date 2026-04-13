from typing import ClassVar
import orjson as json

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django_filters import rest_framework as filters
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ParseError
from rest_framework.filters import OrderingFilter
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from rules.es_graphs import (
    ESDeleteAlertsBySid,
    ESError,
    ESSigsListHits,
    ESTopRules,
)
from rules.models.model import (
    CategoryTransformation,
    Ruleset,
    RulesetTransformation,
    RuleTransformation,
    Transformation,
    Rule,
    RuleAtVersion,
    UserAction,
)
from rules.api.permissions import NoPermission, edit_rule_permission
from rules.services.transformation import TransformationService
from rules.suripyg import SuriHTMLFormat
from scirius.rest_utils import (
    ESManageMultipleESIndexesViewSet,
    SciriusReadOnlyModelViewSet,
)
from scirius.utils import get_middleware_module

from .category import CategorySerializer
from .common import CommentSerializer, ListFilter

Probe = __import__(settings.RULESET_MIDDLEWARE)


class RuleAtVersionSerializer(serializers.ModelSerializer):
    analysis = serializers.SerializerMethodField()
    content_html = serializers.SerializerMethodField()

    class Meta:
        model = RuleAtVersion
        exclude = ("rule",)

    def get_analysis(self, instance):
        if instance.analysis:
            return json.loads(instance.analysis)
        return None

    def get_content_html(self, instance):
        return SuriHTMLFormat(instance.content)


class RuleFilter(filters.FilterSet):
    min_created = filters.DateFilter(field_name="ruleatversion__created", lookup_expr="gte")
    max_created = filters.DateFilter(field_name="ruleatversion__created", lookup_expr="lte")
    created = filters.DateFilter(field_name="ruleatversion__created", lookup_expr="exact")
    min_updated = filters.DateFilter(field_name="ruleatversion__updated", lookup_expr="gte")
    max_updated = filters.DateFilter(field_name="ruleatversion__updated", lookup_expr="lte")
    updated = filters.DateFilter(field_name="ruleatversion__updated", lookup_expr="exact")
    msg = ListFilter(field_name="msg", lookup_expr="icontains")
    not_in_msg = ListFilter(field_name="msg", lookup_expr="icontains", exclude=True)
    content = ListFilter(field_name="ruleatversion__content", lookup_expr="icontains")
    not_in_content = ListFilter(field_name="ruleatversion__content", lookup_expr="icontains", exclude=True)
    analysis_isnull = filters.BooleanFilter(field_name="ruleatversion__analysis", method="filter_analysis")

    class Meta:
        model = Rule
        fields: ClassVar[list[str]] = [
            "sid",
            "category",
            "msg",
            "not_in_msg",
            "content",
            "not_in_content",
            "ruleatversion__created",
            "ruleatversion__updated",
        ]
        extra_kwargs: ClassVar[dict[str, dict[str, str]]] = {
            "not_in_msg": {"source": "msg"},
            "not_in_content": {"source": "content"},
        }

    def filter_analysis(self, queryset, name: str, value):
        lookup = f"{name}__isnull"
        return queryset.filter(**{lookup: value})


class RuleChangeSerializer(serializers.Serializer):
    ruleset = serializers.PrimaryKeyRelatedField(queryset=Ruleset.objects.all(), write_only=True)
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True)


class HitTimelineEntry(serializers.Serializer):
    date = serializers.IntegerField(read_only=True)
    hits = serializers.IntegerField(read_only=True)


class ProbeEntry(serializers.Serializer):
    probe = serializers.CharField(read_only=True)
    hits = serializers.IntegerField(read_only=True)


class RuleSerializer(serializers.ModelSerializer):
    category = CategorySerializer(read_only=True)
    hits = serializers.IntegerField(read_only=True)
    timeline_data = HitTimelineEntry(many=True, read_only=True)
    probes = ProbeEntry(many=True, read_only=True)
    versions = RuleAtVersionSerializer(source="ruleatversion_set", many=True, read_only=True)

    class Meta:
        model = Rule
        fields = ("pk", "sid", "category", "msg", "created", "updated", "hits", "timeline_data", "versions", "probes")

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data.update(get_middleware_module("common").get_threat_info_from_sid(instance.sid))
        return data


class RuleHitsOrderingFilter(OrderingFilter, ESManageMultipleESIndexesViewSet):
    def get_query_param(self, request, param):
        value = request.query_params.get(param)
        if value is not None:
            try:
                if "," in value:
                    values = [int(x) for x in value.split(",")]
                    if param == "hits_min":
                        return max(values)
                    return min(values)

                value = int(value)
            except ValueError:
                value = None
        return value

    def _get_hits_order(self, request, order):
        try:
            result = ESTopRules(request, view=self).get(count=Rule.objects.count(), order=order)
        except ESError:
            queryset = Rule.objects.order_by("sid")
            queryset = queryset.annotate(hits=models.Value(0, output_field=models.IntegerField()))
            queryset = queryset.annotate(
                hits=models.ExpressionWrapper(models.Value(0), output_field=models.IntegerField())
            )
            return queryset.values_list("sid", "hits")

        return [(x["key"], x["doc_count"]) for x in result]

    def _filter_min_max(self, request, queryset, hits_order):
        hits_by_sid = dict(hits_order)

        min_hits = self.get_query_param(request, "hits_min")
        max_hits = self.get_query_param(request, "hits_max")
        sids = list(queryset.values_list("sid", flat=True))

        if min_hits is not None or max_hits is not None:
            if min_hits is not None and max_hits is not None:
                return [
                    sid
                    for sid in sids
                    if hits_by_sid.get(sid, 0) >= min_hits and hits_by_sid.get(sid, max_hits + 1) <= max_hits
                ]
            if min_hits is not None and max_hits is None:
                return [sid for sid in sids if hits_by_sid.get(sid, 0) >= min_hits]
            if min_hits is None and max_hits is not None:
                return [sid for sid in sids if hits_by_sid.get(sid, max_hits + 1) <= max_hits]

        return list(queryset.values_list("sid", flat=True))

    def filter_queryset(self, request, queryset, view):
        ordering = self.get_ordering(request, queryset, view)
        queryset = get_middleware_module("common").filter_event_types(request, queryset, view)

        if "hits" in ordering or "-hits" in ordering:
            if ordering[0] not in ("hits", "-hits"):
                raise ParseError("hits ordering can only be the first ordering term")

            hits_ordering = ordering[0]
            ordering = ordering[1:]

            if ordering:
                ordering = tuple(list(ordering) + ["sid"])
                queryset = queryset.order_by(*ordering)

            # Sorting
            order = "asc" if hits_ordering == "hits" else "desc"
            hits_order = self._get_hits_order(request, order)
            rules = self._filter_min_max(request, queryset, hits_order)

            sids = []
            for sid, _ in hits_order:
                if sid in rules:
                    sids.append(sid)
                    rules.remove(sid)

            # We add rules with no hits
            if order == "desc":
                sids += rules
            else:
                sids = rules + sids

        else:
            if ordering:
                ordering = tuple(list(ordering) + ["sid"])
                queryset = queryset.order_by(*ordering)

            if (
                self.get_query_param(request, "hits_min") is not None or self.get_query_param(request, "hits_max") is not None
            ):
                hits_order = self._get_hits_order(request, "asc")
                return self._filter_min_max(request, queryset, hits_order)

            sids = list(queryset.values_list("sid", flat=True))

        return sids


@extend_schema(tags=["Rule"])
class RuleViewSet(SciriusReadOnlyModelViewSet, ESManageMultipleESIndexesViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show a rule and its none transformed content:\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":300000000,"sid":300000000,"category":{"pk":1403,"name":"Suricata Traffic ID ruleset Sigs","descr":"","created_date":"2018-07-18T13:54:05.045025+02:00","source":69},
        "msg":"SURICATA TRAFFIC-ID: bing","state":true,"state_in_source":true,"rev":1,"content":"alert tls any any -> any any (msg:\"SURICATA TRAFFIC-ID: bing\"; tls_sni; content:\"bing.com\";
        isdataat:!1,relative; flow:to_server,established; flowbits: set,traffic/id/bing; flowbits:set,traffic/label/search; noalert; sid:300000000; rev:1;)\\n","imported_date":"2018-07-18T13:54:05.153618+02:00","updated_date":"2018-07-18T13:54:05.153618+02:00"}

    Show a rule and its none transformed content in html:\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/?highlight=true -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":300000000,"sid":300000000,"category":{"pk":1403,"name":"Suricata Traffic ID ruleset Sigs","descr":"","created_date":"2018-07-18T13:54:05.045025+02:00","source":69},
        "msg":"SURICATA TRAFFIC-ID: bing","state":true,"state_in_source":true,"rev":1,"content":"<div class=\"highlight\"><pre><span></span><span class=\"kt\">alert</span><span class=\"w\"> </span>
        <span class=\"err\">tls</span><span class=\"w\"> </span><span class=\"nv\">any</span><span class=\"w\"> </span><span class=\"nv\">any</span><span class=\"w\"> </span><span class=\"o\">-&gt;</span>
        <span class=\"w\"> </span><span class=\"nv\">any</span><span class=\"w\"> </span><span class=\"nv\">any</span><span class=\"w\"> </span><span class=\"err\">(</span><span class=\"k\">msg:</span>
        <span class=\"s\">&quot;SURICATA TRAFFIC-ID: bing&quot;</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"err\">tls_sni</span><span class=\"p\">;</span><span class=\"w\"> </span>
        <span class=\"k\">content:</span><span class=\"s\">&quot;bing.com&quot;</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">isdataat:</span><span class=\"err\">!</span>
        <span class=\"m\">1</span><span class=\"err\">,</span><span class=\"na\">relative</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">flow:</span><span class=\"na\">to_server</span>
        <span class=\"err\">,</span><span class=\"na\">established</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">flow</span><span class=\"err\">bits</span><span class=\"k\">:</span>
        <span class=\"w\"> </span><span class=\"na\">set</span><span class=\"err\">,traffic/</span><span class=\"k\">id</span><span class=\"err\">/bing</span><span class=\"p\">;</span><span class=\"w\"> </span>
        <span class=\"k\">flow</span><span class=\"err\">bits</span><span class=\"k\">:</span><span class=\"na\">set</span><span class=\"err\">,traffic/label/search</span><span class=\"p\">;</span><span class=\"w\"> </span>
        <span class=\"k\">noalert</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">sid:</span><span class=\"m\">300000000</span><span class=\"p\">;</span><span class=\"w\"> </span>
        <span class=\"k\">rev:</span><span class=\"m\">1</span><span class=\"p\">;</span><span class=\"err\">)</span><span class=\"w\"></span>\\n</pre></div>\\n","imported_date":"2018-07-18T13:54:05.153618+02:00","updated_date":"2018-07-18T13:54:05.153618+02:00"}

    Show a transformed rule content:\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/content/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"2":"drop ip $HOME_NET any -> [101.200.81.187,103.19.89.118,103.230.84.239,103.4.52.150,103.7.59.135] any (msg:\\"ET CNC Zeus Tracker Reported CnC Server group 1\\"; reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,zeustracker.abuse.ch; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404150; rev:4984;)"}

    Get rule status in its rulesets:\n
        curl -v -k https://x.x.x.x/rest/rules/rule/<sid-rule>/status/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"1":{"active":true,"valid":{"status":true,"errors":""},"name":"Ruleset1","transformations":{"action":"reject","lateral":null,"target":null}},"2":{"active":true,"valid":{"status":true,"errors":""},"name":"copyRuleset1","transformations":{"action":"reject","lateral":null,"target":null}},"4":{"active":true,"valid":{"status":true,"errors":""},"name":"copyRuleset123","transformations":{"action":"reject","lateral":null,"target":null}}}

    Show a transformed rule content in html:\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/content/?highlight=true -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Get rule's comments:\n
        curl -v -k https://x.x.x.x/rest/rules/rule/<sid-rule>/comment/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"1":"<div class=\"highlight\"><pre><span></span><span class=\"kt\">drop</span><span class=\"w\"> </span><span class=\"kc\">ip</span><span class=\"w\"> </span>
        <span class=\"nv\">$HOME_NET</span><span class=\"w\"> </span><span class=\"nv\">any</span><span class=\"w\"> </span><span class=\"o\">-&gt;</span><span class=\"w\"> </span>
        <span class=\"err\">[</span><span class=\"nv\">109.196.130.50</span><span class=\"err\">,</span><span class=\"nv\">151.13.184.200</span><span class=\"err\">]</span>
        <span class=\"w\"> </span><span class=\"nv\">any</span><span class=\"w\"> </span><span class=\"err\">(</span><span class=\"k\">msg:</span>
        <span class=\"s\">&quot;ET CNC Shadowserver Reported CnC Server IP group 1&quot;</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">reference:</span>
        <span class=\"nv\">url</span><span class=\"p\">,</span><span class=\"na\">doc.emergingthreats.net/bin/view/Main/BotCC</span><span class=\"p\">;</span><span class=\"w\"> </span>
        <span class=\"k\">reference:</span><span class=\"nv\">url</span><span class=\"p\">,</span><span class=\"na\">www.shadowserver.org</span><span class=\"p\">;</span>
        <span class=\"w\"> </span><span class=\"k\">threshold:</span><span class=\"w\"> </span><span class=\"na\">type</span><span class=\"w\"> </span><span class=\"na\">limit</span>
        <span class=\"err\">,</span><span class=\"w\"> </span><span class=\"na\">track</span><span class=\"w\"> </span><span class=\"na\">by_src</span><span class=\"err\">,</span>
        <span class=\"w\"> </span><span class=\"na\">seconds</span><span class=\"w\"> </span><span class=\"m\">3600</span><span class=\"err\">,</span><span class=\"w\"> </span>
        <span class=\"na\">count</span><span class=\"w\"> </span><span class=\"m\">1</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">flow</span>
        <span class=\"err\">bits</span><span class=\"k\">:</span><span class=\"na\">set</span><span class=\"err\">,ET.Evil</span><span class=\"p\">;</span><span class=\"w\"> </span>
        <span class=\"k\">flow</span><span class=\"err\">bits</span><span class=\"k\">:</span><span class=\"na\">set</span><span class=\"err\">,ET.BotccIP</span><span class=\"p\">;</span>
        <span class=\"w\"> </span><span class=\"k\">classtype:</span><span class=\"err\">trojan-activity</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">sid:</span>
        <span class=\"m\">2404000</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">rev:</span><span class=\"m\">5032</span><span class=\"p\">;</span>
        <span class=\"err\">)</span><span class=\"w\"></span>\\n</pre></div>\\n"}

    Filter by action/reject on all transformed rules:\n
        curl -k https://x.x.x.x/rest/rules/rule/transformation/?transfo_type=action&transfo_value=reject -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    ==== POST ====\n
    Disable a rule in a ruleset.\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/disable/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>}'

    Return:\n
        HTTP/1.1 200 OK
        {"disable":"ok"}

    Enable a rule in a ruleset.:\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/enable/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>}'

    Return:\n
        HTTP/1.1 200 OK
        {"enable":"ok"}

    Comment a rule:\n
        curl -v -k https://x.x.x.x/rest/rules/rule/<sid-rule>/comment/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"comment": "comment this rule"}'

    Return:\n
        HTTP/1.1 200 OK
        {"comment":"ok"}

    Toggle availabililty on all versions of the rule:\n
        curl -v -k https://x.x.x.x/rest/rules/rule/<sid-rule>/toggle_availability/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"comment": "toggle rule"}'

    Toggle availabililty on specific version of the rule:\n
        curl -v -k https://x.x.x.x/rest/rules/rule/<sid-rule>/toggle_availability/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"comment": "toggle rule", "version": 39}'

        curl -v -k https://x.x.x.x/rest/rules/rule/<sid-rule>/toggle_availability/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"comment": "toggle rule", "version": 0}'

    Return:\n
        HTTP/1.1 200 OK
        {"toggle_availability":"ok"}

    =============================================================================================================================================================
    """

    queryset = Rule.objects.all()
    serializer_class = RuleSerializer
    ordering = ("sid",)
    ordering_fields = (
        "sid",
        "category",
        "msg",
        "ruleatversion__imported_date",
        "ruleatversion__updated_date",
        "created",
        "updated",
        "hits",
    )
    filter_backends = (DjangoFilterBackend, RuleHitsOrderingFilter)
    filterset_class = RuleFilter
    REQUIRED_GROUPS = {
        "READ": ("rules.ruleset_policy_view",),
        "WRITE": ("rules.ruleset_policy_edit",),
    }

    def get_permissions(self):
        if self.action == "delete_alerts":
            if not self.request.user.has_perm("rules.events_edit"):
                return [NoPermission()]
            return [IsAuthenticated()]
        return super().get_permissions()

    @action(detail=True, methods=["get"])
    def references(self, request, pk):
        rule = self.get_object()
        references = rule.extract_rule_references()

        res = []
        for reference in references:
            res.append({"url": reference.url, "key": reference.key, "value": reference.value})

        return Response(res)

    @action(detail=True, methods=["post"])
    def delete_alerts(self, request, pk):
        # return 404 error if pk does not exist
        self.get_object()

        if hasattr(Probe.common, "es_delete_alerts_by_sid"):
            result = Probe.common.es_delete_alerts_by_sid(pk, request=request)
        else:
            errors = ESDeleteAlertsBySid(request).get(pk)
            if errors:
                return Response({"details": "\n".join(errors)}, status=500)
            return Response({"delete_alerts": "ok"})
        return Response(result)

    @action(detail=False, methods=["get"])
    def transformation(self, request):
        service = TransformationService()
        try:
            key_str, value_str = service.validate_transformation_filter(request.query_params.dict())
        except ValueError as exc:
            raise serializers.ValidationError(exc.args[0]) from exc
        res = service.get_transformed_rules(key_str, value_str)
        return Response(res)

    @action(detail=True, methods=["get"])
    def content(self, request, pk):
        rule = self.get_object()
        rulesets = Ruleset.objects.filter(categories__rule=rule)
        highlight_str = request.query_params.get("highlight", "false")

        def is_highlight(value):
            return bool(value) and value.lower() not in ("false", "0")

        highlight = is_highlight(highlight_str)

        res = {}
        for ruleset in rulesets:
            for rav in rule.ruleatversion_set.all():
                if ruleset.pk not in res:
                    res[ruleset.pk] = {}
                content = rav.generate_content(ruleset)
                res[ruleset.pk][rav.version] = content if not highlight else SuriHTMLFormat(content)

        return Response(res)

    @action(detail=True, methods=["get", "post"])
    def comment(self, request, pk):
        if request.method == "POST":
            rule = self.get_object()
            comment = request.data.get("comment", None)

            comment_serializer = CommentSerializer(data={"comment": comment})
            comment_serializer.is_valid(raise_exception=True)

            UserAction.create(action_type="comment_rule", comment=comment, request=request, rule=rule)
            return Response({"comment": "ok"})
        if request.method == "GET":
            rule = self.get_object()
            uas = rule.get_comments()
            res = {rule.sid: []}
            for ua in uas:
                res[rule.sid].append(
                    {
                        "title": ua.get_title(),
                        "icon": ua.get_icons(),
                        "comment": ua.comment if len(ua.comment) else "No comment",
                        "description": ua.generate_description(request.user),
                        "date": ua.date,
                    }
                )
            return Response(res)
        return None

    @action(detail=True, methods=["post"])
    @edit_rule_permission()
    def toggle_availability(self, request, pk):
        rule = self.get_object()
        comment = request.data.get("comment", None)
        version = request.data.get("version", None)

        comment_serializer = CommentSerializer(data={"comment": comment})
        comment_serializer.is_valid(raise_exception=True)

        rule.toggle_availability(version=version)

        UserAction.create(action_type="toggle_availability", comment=comment, request=request, rule=rule)

        return Response({"toggle_availability": "ok"})

    @action(detail=True, methods=["post"])
    @edit_rule_permission()
    def enable(self, request, pk):
        rule = self.get_object()
        serializer = RuleChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rule.enable(serializer.validated_data["ruleset"], request, serializer.validated_data.get("comment", None))
        return Response({"enable": "ok"})

    @action(detail=True, methods=["post"])
    @edit_rule_permission()
    def disable(self, request, pk):
        rule = self.get_object()
        serializer = RuleChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rule.disable(serializer.validated_data["ruleset"], request, serializer.validated_data.get("comment", None))
        return Response({"disable": "ok"})

    def get_serializer_class(self):
        if self.action in ("enable", "disable"):
            return RuleChangeSerializer
        return RuleSerializer

    @action(detail=True, methods=["get"])
    def status(self, request, pk):
        rule = self.get_object()

        res = {}
        for ruleset in Ruleset.objects.all():
            res[ruleset.pk] = {}
            res[ruleset.pk]["name"] = ruleset.name
            # is tested only on version 0
            res[ruleset.pk]["valid"] = rule.test(ruleset)

            for rav in rule.ruleatversion_set.all():
                res[ruleset.pk][rav.version] = {
                    "active": rav.is_active(ruleset),
                }

            res[ruleset.pk]["transformations"] = {}
            _service = TransformationService()
            for key in (Transformation.ACTION, Transformation.LATERAL, Transformation.TARGET):
                trans = _service.get_for_rule(rule, ruleset, key, override=True)
                res[ruleset.pk]["transformations"][key.value] = trans.value if trans else None

        return Response(res)

    def _scirius_hit(self, r):
        timeline = []
        for entry in r["timeline"]["buckets"]:
            timeline.append({"date": entry["key"], "hits": entry["doc_count"]})

        probes = []
        for entry in r["probes"]["buckets"]:
            probes.append({"probe": entry["key"], "hits": entry["doc_count"]})

        return {"hits": r["doc_count"], "timeline_data": timeline, "probes": probes}

    def _add_hits(self, request, data):
        sids = ",".join([str(rule["sid"]) for rule in data])

        try:
            result = ESSigsListHits(request, view=self).get(sids)
        except ESError:
            return data

        # reformat ES's output
        hits = {}
        for r in result:
            hits[r["key"]] = self._scirius_hit(r)

        for rule in data:
            sid = rule["sid"]
            if sid in hits:
                rule.update(hits[sid])
            else:
                rule.update({"hits": 0, "timeline_data": [], "probes": []})
        return data

    def get_object(self):
        sids = self.filter_queryset(self.get_queryset())
        queryset = Rule.objects.filter(sid__in=sids)

        # Perform the lookup filtering.
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field

        if lookup_url_kwarg not in self.kwargs:
            raise ValidationError(
                f"Expected view {self.__class__.__name__} to be called with a URL keyword argument "
                f'named "{lookup_url_kwarg}". Fix your URL conf, or set the `.lookup_field` '
                "attribute on the view correctly."
            )

        filter_kwargs = {self.lookup_field: self.kwargs[lookup_url_kwarg]}
        obj = get_object_or_404(queryset, **filter_kwargs)

        # May raise a permission denied
        self.check_object_permissions(self.request, obj)

        return obj

    def list(self, request):
        sids = self.filter_queryset(self.get_queryset())
        pks = self.paginate_queryset(sids)
        page = [Rule.objects.get(pk=pk) for pk in pks]
        serializer = self.get_serializer(page, many=True)
        self._add_hits(request, serializer.data)
        return self.get_paginated_response(serializer.data)


class BaseTransformationViewSet(viewsets.ModelViewSet):
    def _get_service(self) -> TransformationService:
        return TransformationService()

    def create(self, request, *args, **kwargs):
        key = request.data.get("transfo_type")
        value = request.data.get("transfo_value")
        comment = request.data.get("comment")

        service = self._get_service()
        try:
            service.validate_key_value(key, value)
        except ValueError as exc:
            raise serializers.ValidationError(exc.args[0]) from exc

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if isinstance(self, RuleTransformationViewSet):
            try:
                service.validate_rule_choices(
                    serializer.validated_data["rule_transformation"],
                    Transformation.Type(key),
                    value,
                )
            except ValueError as exc:
                raise serializers.ValidationError(exc.args[0]) from exc

        serializer.save()
        service.log_create(serializer.validated_data, self._fields, self._action_type, request.user, comment)

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        comment = request.data.get("comment")

        service = self._get_service()
        service.log_delete(instance, self._fields, f"delete_{self._action_type}", request.user, comment)

        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        key = request.data.get("transfo_type")
        value = request.data.get("transfo_value")
        comment = request.data.get("comment")

        service = self._get_service()
        try:
            service.validate_key_value(key, value)
        except ValueError as exc:
            raise serializers.ValidationError(exc.args[0]) from exc

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.instance.clean()
        serializer.is_valid(raise_exception=True)
        serializer.save()

        service.log_update(
            instance, serializer.validated_data, self._fields, self._action_type, request.user, comment, partial=partial
        )

        if getattr(instance, "_prefetched_objects_cache", None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def partial_update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)


class CategoryTransformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CategoryTransformation
        fields = ("pk", "ruleset", "category", "transfo_type", "transfo_value")
        extra_kwargs = {
            "category": {"source": "category_transformation"},
            "transfo_type": {"source": "key"},
            "transfo_value": {"source": "value"},
        }


@extend_schema(tags=["Source", "Transformation"])
class CategoryTransformationViewSet(BaseTransformationViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show a category transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformation/category/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":2,"ruleset":9,"category":27,"transfo_type":"action","transfo_value":"drop"}

    ==== POST ====\n
    Create a category ACTION transformation: (drop / reject / filestore / bypass / none)\n
        curl -k https://x.x.x.x/rest/rules/transformation/category/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "action", "transfo_value": "drop"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":3,"ruleset":9,"category":27,"transfo_type":"lateral","transfo_value":"yes"}

    Create a category TARGET transformation: (src / dst / auto / none)\n
        curl -k https://x.x.x.x/rest/rules/transformation/category/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "target", "transfo_value": "src"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":4,"ruleset":9,"category":27,"transfo_type":"target","transfo_value":"src"}

    Create a category LATERAL transformation (yes / auto / no):\n
        curl -k https://x.x.x.x/rest/rules/transformation/category/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "lateral", "transfo_value": "yes"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":5,"ruleset":9,"category":27,"transfo_type":"lateral","transfo_value":"yes"}

    ==== PATCH ====\n
    Patch a category transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformation/category/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"transfo_type": "target", "transfo_value": "dst"}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":2,"ruleset":9,"category":27,"transfo_type":"action","transfo_value":"reject"}

    ==== PUT ====\n
    Replace a category transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformation/category/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "action", "transfo_value": "drop"}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":2,"ruleset":9,"category":27,"transfo_type":"action","transfo_value":"reject"}

    ==== DELETE ====\n
    Delete a category transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformation/category/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """

    queryset = CategoryTransformation.objects.all()
    serializer_class = CategoryTransformationSerializer
    ordering = ("pk",)
    filterset_fields = ("category_transformation", "ruleset")
    ordering_fields = ("pk", "ruleset", "category_transformation")
    _fields = {"ruleset": "ruleset", "trans_type": "key", "trans_value": "value", "category": "category_transformation"}
    _action_type = "transform_category"
    REQUIRED_GROUPS = {
        "READ": ("rules.ruleset_policy_view",),
        "WRITE": ("rules.ruleset_policy_edit",),
    }


class RulesetTransformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = RulesetTransformation
        fields = ("pk", "ruleset", "transfo_type", "transfo_value")

        extra_kwargs = {
            "ruleset": {"source": "ruleset_transformation"},
            "transfo_type": {"source": "key"},
            "transfo_value": {"source": "value"},
        }


@extend_schema(tags=["Ruleset", "Transformation"])
class RulesetTransformationViewSet(BaseTransformationViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show a ruleset transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformation/ruleset/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":5,"ruleset":2,"transfo_type":"action","transfo_value":"drop"}

    ==== POST ====\n
    Create a ruleset ACTION transformation (drop / reject / filestore / bypass / none):\n
        curl -k https://x.x.x.x/rest/rules/transformation/ruleset/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "action", "transfo_value": "drop"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":5,"ruleset":2,"transfo_type":"action","transfo_value":"drop"}

    Create a ruleset TARGET transformation (src / dst / auto / none):\n
        curl -k https://x.x.x.x/rest/rules/transformation/ruleset/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "target", "transfo_value": "src"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":5,"ruleset":2,"transfo_type":"target","transfo_value":"src"}

    Create a ruleset LATERAL transformation (yes / auto / no):\n
        curl -k https://x.x.x.x/rest/rules/transformation/ruleset/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "lateral", "transfo_value": "yes"}'

    ==== PATCH ====\n
    Patch a ruleset transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformation/ruleset/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"transfo_type": "target", "transfo_value": "dst"}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":5,"ruleset":2,"transfo_type":"action","transfo_value":"reject"}

    ==== PUT ====\n
    Replace a ruleset transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformation/ruleset/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"ruleset": <pk-ruleset>,  "transfo_type": "action", "transfo_value": "drop"}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":5,"ruleset":2,"transfo_type":"action","transfo_value":"drop"}

    ==== DELETE ====\n
    Delete a ruleset transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformation/ruleset/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """

    queryset = RulesetTransformation.objects.all()
    serializer_class = RulesetTransformationSerializer
    ordering = ("pk",)
    filterset_fields = ("ruleset_transformation",)
    ordering_fields = ("ruleset_transformation",)
    _fields = {"ruleset": "ruleset_transformation", "trans_type": "key", "trans_value": "value"}
    _action_type = "transform_ruleset"
    REQUIRED_GROUPS = {
        "READ": ("rules.ruleset_policy_view",),
        "WRITE": ("rules.ruleset_policy_edit",),
    }


class RuleTransformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleTransformation
        fields = ("pk", "ruleset", "rule", "transfo_type", "transfo_value")
        extra_kwargs = {
            "rule": {"source": "rule_transformation"},
            "transfo_type": {"source": "key"},
            "transfo_value": {"source": "value"},
        }


@extend_schema(tags=["Rule", "Transformation"])
class RuleTransformationViewSet(BaseTransformationViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show all transformed rules:\n
        curl -k https://x.x.x.x/rest/rules/transformation/rule/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"count":1,"next":null,"previous":null,"results":[{"pk":4,"ruleset":7,"rule":2404000,"transfo_type":"action","transfo_value":"drop"}]}

    Show a rule transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformation/rule/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":3,"ruleset":9,"rule":2404150,"transfo_type":"action","transfo_value":"drop"}

    ==== POST ====\n
    Create a rule ACTION transformation (drop / reject / filestore / bypass / none):\n
        curl -k https://x.x.x.x/rest/rules/transformation/rule/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "action", "transfo_value": "reject"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":4,"ruleset":9,"rule":2404150,"transfo_type":"action","transfo_value":"reject"}

    Create a rule TARGET transformation: (src / dst / auto / none)\n
        curl -k https://x.x.x.x/rest/rules/transformation/rule/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "target", "transfo_value": "src"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":5,"ruleset":9,"rule":2404150,"transfo_type":"target","transfo_value":"src"}

    Create a rule LATERAL transformation (yes / auto / no):\n
        curl -k https://x.x.x.x/rest/rules/transformation/rule/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "lateral", "transfo_value": "yes"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":6,"ruleset":9,"rule":2404150,"transfo_type":"lateral","transfo_value":"yes"}

    ==== PATCH ====\n
    Patch a rule transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformation/rule/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"transfo_type": "action", "transfo_value": "drop"}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":4,"ruleset":9,"rule":2404150,"transfo_type":"action","transfo_value":"drop"}

    ==== PUT ====\n
    Replace a rule transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformation/rule/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "action", "transfo_value": "bypass"}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":4,"ruleset":9,"rule":2404150,"transfo_type":"action","transfo_value":"bypass"}

    ==== DELETE ====\n
    Delete a rule:\n
        curl -k https://x.x.x.x/rest/rules/transformation/rule/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """

    queryset = RuleTransformation.objects.all()
    serializer_class = RuleTransformationSerializer
    ordering = ("pk",)
    filterset_fields = ("rule_transformation", "ruleset")
    ordering_fields = ("pk", "ruleset", "rule_transformation")
    _fields = {"ruleset": "ruleset", "trans_type": "key", "trans_value": "value", "rule": "rule_transformation"}
    _action_type = "transform_rule"
    REQUIRED_GROUPS = {
        "READ": ("rules.ruleset_policy_view",),
        "WRITE": ("rules.ruleset_policy_edit",),
    }
