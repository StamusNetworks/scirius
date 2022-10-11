
from .suripyg import SuriHTMLFormat

from django.conf import settings
from django.urls import re_path
from django.utils import timezone
from django.db import models
from collections import OrderedDict
import json

from django.core.exceptions import SuspiciousOperation, ValidationError

from rest_framework.views import APIView
from rest_framework.validators import UniqueValidator
from rest_framework import serializers, viewsets, exceptions
from rest_framework.decorators import action
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import OrderingFilter
from rest_framework.response import Response
from rest_framework.exceptions import APIException, ParseError, PermissionDenied
from rest_framework.routers import DefaultRouter
from rest_framework import status
from rest_framework.parsers import MultiPartParser, JSONParser
from rest_framework.mixins import UpdateModelMixin, RetrieveModelMixin
from rules.rest_permissions import NoPermission
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import get_object_or_404

from django_filters import rest_framework as filters
from elasticsearch.exceptions import ConnectionError

from rules.models import Rule, Category, Ruleset, RuleTransformation, CategoryTransformation, RulesetTransformation, FilterSet
from rules.models import Source, SourceAtVersion, SourceUpdate, UserAction, UserActionObject, Transformation, SystemSettings, get_system_settings
from rules.views import get_public_sources, fetch_public_sources, extract_rule_references
from rules.rest_processing import RuleProcessingFilterViewSet
from rules.es_data import ESData
from rules.es_query import build_es_url, ESPaginator

from rules.es_graphs import ESStats, ESRulesStats, ESSidByHosts, ESFieldStats, ESShardStats
from rules.es_graphs import ESTimeline, ESMetricsTimeline, ESHealth, ESRulesPerCategory, ESAlertsCount, ESAlertsTrend, ESTimeRangeAllAlerts, ESFlowTimeline, \
    ESIPFlowTimeline
from rules.es_graphs import ESLatestStats, ESIppairAlerts, ESIppairNetworkAlerts, ESEventsTail, ESSuriLogTail, ESPoststats, ESEventsTimeline
from rules.es_graphs import ESSigsListHits, ESTopRules, ESError, ESDeleteAlertsBySid, ESEventsFromFlowID, ESFieldsStats

from rules.es_analytics import ESGetUniqueFields
from rules.es_analytics import ESGraphAgg, ESFieldUniqAgg

from scirius.rest_utils import SciriusReadOnlyModelViewSet
from scirius.settings import USE_EVEBOX, USE_KIBANA, KIBANA_PROXY, KIBANA_URL, ELASTICSEARCH_KEYWORD, USE_CYBERCHEF, CYBERCHEF_URL

Probe = __import__(settings.RULESET_MIDDLEWARE)


class ServiceUnavailableException(APIException):
    status_code = 500
    default_detail = 'Internal Server Error.'
    default_code = 'internal_error'


class ModelSerializer(serializers.ModelSerializer):
    def field_changed(self, field):
        if field not in self._validated_data:
            return False
        if self.instance is None:
            return True
        return getattr(self.instance, field) != self._validated_data[field]

    def get_field_val(self, field, data):
        if field in data:
            return data[field]
        if self.instance is not None:
            return getattr(self.instance, field)
        return None


class CommentSerializer(serializers.Serializer):
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True, allow_null=True)


class CopyRulesetSerializer(serializers.Serializer):
    name = serializers.CharField(required=True, allow_blank=False, validators=[UniqueValidator(queryset=Ruleset.objects.all())])


class RulesetSerializer(serializers.ModelSerializer):
    sources = serializers.PrimaryKeyRelatedField(queryset=Source.objects.all(), many=True, required=False)
    categories = serializers.PrimaryKeyRelatedField(queryset=Category.objects.all(), many=True, required=False)
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True, allow_null=True)
    warnings = serializers.CharField(required=False, allow_blank=True, read_only=True, allow_null=True)

    class Meta:
        model = Ruleset
        fields = ('pk', 'name', 'descr', 'created_date', 'updated_date', 'need_test', 'validity',
                  'errors', 'rules_count', 'sources', 'categories', 'comment', 'warnings')
        read_only_fields = ('pk', 'created_date', 'updated_date', 'need_test', 'validity', 'errors',
                            'rules_count', 'warnings')

    def create(self, validated_data):
        validated_data['created_date'] = timezone.now()
        validated_data['updated_date'] = timezone.now()
        instance = super(RulesetSerializer, self).create(validated_data)
        return instance

    def to_representation(self, instance):
        data = super(RulesetSerializer, self).to_representation(instance)
        sources_at_version = instance.sources
        sources = Source.objects.filter(sourceatversion__in=sources_at_version.all())
        data['sources'] = [source.pk for source in sources]

        try:
            from scirius.utils import get_middleware_module
            data.update(get_middleware_module('common').get_rest_ruleset(instance))
        except AttributeError:
            pass
        return data

    def to_internal_value(self, data):
        data = super(RulesetSerializer, self).to_internal_value(data)

        if 'sources' not in data:
            return data

        sources = SourceAtVersion.objects.filter(source__in=data['sources'])
        data['sources'] = list(sources)
        return data


class RulesetViewSet(viewsets.ModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Ruleset detail:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":9,"name":"MyCreatedRuleset","descr":"","created_date":"2018-05-04T16:10:43.698843+02:00","updated_date":"2018-05-04T16:10:43.698852+02:00","need_test":true,"validity":true,"errors":"\\"\\"","rules_count":204,"sources":[1],"categories":[27]}

    ==== POST ====\n
    Create a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"name": "SonicRuleset", "sources": [pk-source1, ..., pk-sourceN], "categories": [pk-category1, ..., pk-categoryN]}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":12,"name":"SonicRuleset","descr":"","created_date":"2018-05-07T11:27:21.482840+02:00","updated_date":"2018-05-07T11:27:21.482853+02:00","need_test":true,"validity":true,"errors":"","rules_count":0,"sources":[1],"categories":[27]}

    Copy a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/copy/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST  -d '{"name": "copyRuleset1", "comment": "need a clone"}'

    Return:\n
        HTTP/1.1 200 OK
        {"copy":"ok"}

    ==== PATCH ====\n
    Patch a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"name": "PatchedSonicRuleset", "categories": [pk-category1, ..., pk-categoryN]}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":12,"name":"SonicRulesetPatched","descr":"","created_date":"2018-05-07T11:27:21.482840+02:00","updated_date":"2018-05-07T11:27:21.482853+02:00","need_test":false,"validity":true,"errors":"\\"\\"","rules_count":204,"sources":[1],"categories":[27,1]}

    ==== PUT ====\n
    Replace a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"name": "ReplacedSonicRuleset", "comment": "sonic comment", "sources": [pk-source1, ..., pk-sourceN, "categories": [pk-category1, ..., pk-categoryN]}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":12,"name":"SonicRulesetReplaced","descr":"","created_date":"2018-05-07T11:27:21.482840+02:00","updated_date":"2018-05-07T11:27:21.482853+02:00","need_test":false,"validity":true,"errors":"\\"\\"","rules_count":204,"sources":[1],"categories":[1]}

    ==== DELETE ====\n
    Delete a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """
    queryset = Ruleset.objects.all()
    serializer_class = RulesetSerializer
    ordering = ('name',)
    ordering_fields = ('name', 'created_date', 'updated_date', 'rules_count')
    filterset_fields = ('name', 'descr')
    REQUIRED_GROUPS = {
        'READ': ('rules.source_view',),
        'WRITE': ('rules.source_edit',),
    }
    no_tenant_check = True

    def _validate_categories(self, sources_at_version, categories):
        if len(sources_at_version) == 0 and len(categories) > 0:
            msg = 'No source selected or wrong selected source(s). Cannot add categories without their source.'
            raise serializers.ValidationError({'sources': [msg]})
        elif len(sources_at_version) > 0 and len(categories) > 0:
            sources = Source.objects.filter(sourceatversion__in=sources_at_version)

            for category in categories:
                if category.source not in sources:
                    msg = 'One or more of categories is/are not in selected sources.'
                    raise serializers.ValidationError({'categories': [msg]})

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        comment = data.pop('comment', None)

        # because of rest website UI
        if isinstance(comment, list):
            comment = comment[0]

        serializer = RulesetSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        # /|\ this is sourceAtVersion because of to_internal_values/to_representation serializer methods
        sources = serializer.validated_data.get('sources', [])
        categories = serializer.validated_data.get('categories', [])
        self._validate_categories(sources, categories)

        serializer.save()
        serializer.instance.number_of_rules()

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
            action_type='create_ruleset',
            comment=comment_serializer.validated_data['comment'],
            request=request,
            ruleset=serializer.instance
        )

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        ruleset = self.get_object()
        comment = request.data.get('comment', None)
        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
            action_type='delete_ruleset',
            request=request,
            ruleset=ruleset,
            comment=comment_serializer.validated_data['comment']
        )
        return super(RulesetViewSet, self).destroy(request, *args, **kwargs)

    def _update_or_partial_update(self, request, partial):
        comment = request.data.get('comment', None)

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        sources = instance.sources.all()
        if 'sources' in serializer.validated_data:
            sources = serializer.validated_data['sources']

        categories = instance.categories.all()
        if 'categories' in serializer.validated_data:
            categories = serializer.validated_data['categories']

        self._validate_categories(sources, categories)

        # This save is used to have the new name if user has edited ruleset name
        serializer.save()
        instance.number_of_rules()

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
            action_type='edit_ruleset',
            comment=comment_serializer.validated_data['comment'],
            request=request,
            ruleset=instance
        )

    def update(self, request, *args, **kwargs):
        self._update_or_partial_update(request, False)
        return super(RulesetViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        self._update_or_partial_update(request, True)
        return super(RulesetViewSet, self).update(request, partial=True, *args, **kwargs)

    @action(detail=True, methods=['post'])
    def copy(self, request, pk):
        data = request.data.copy()
        ruleset = self.get_object()

        comment = data.pop('comment', None)
        copy_serializer = CopyRulesetSerializer(data=data)
        copy_serializer.is_valid(raise_exception=True)

        ruleset.copy(copy_serializer.validated_data['name'])

        UserAction.create(
            action_type='copy_ruleset',
            comment=comment,
            request=request,
            ruleset=ruleset
        )

        return Response({'copy': 'ok'})

    @action(detail=True, methods=['get'])
    def rules_count(self, request, pk):
        ruleset = self.get_object()
        return Response(ruleset.number_of_rules())


class CategoryChangeSerializer(serializers.Serializer):
    ruleset = serializers.PrimaryKeyRelatedField(queryset=Ruleset.objects.all(), write_only=True)
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True)


class CategorySerializer(serializers.ModelSerializer):

    class Meta:
        model = Category
        fields = ('pk', 'name', 'descr', 'created_date', 'source')


class CategoryViewSet(SciriusReadOnlyModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show a category:\n
        curl -k https://x.x.x.x/rest/rules/category/<pk-category>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":127,"name":"emerging-dos","descr":"","created_date":"2018-05-07T14:27:26.620906+02:00","source":9}

    ==== POST ====\n
    Disable a category in a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/category/<pk-category>/disable/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>}'

    Return:\n
        HTTP/1.1 200 OK
        {"disable":"ok"}

    Enable a category in a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/category/<pk-category>/enable/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>}'

    Return:\n
        HTTP/1.1 200 OK
        {"enable":"ok"}

    =============================================================================================================================================================
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    ordering = ('name',)
    ordering_fields = ('pk', 'name', 'created_date', 'source')
    filterset_fields = ('name', 'source')
    REQUIRED_GROUPS = {
        'READ': ('rules.ruleset_policy_view',),
        'WRITE': ('rules.ruleset_policy_edit',),
    }

    @action(detail=True, methods=['post'])
    def enable(self, request, pk):
        category = self.get_object()
        serializer = CategoryChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        category.enable(
            serializer.validated_data['ruleset'],
            request,
            serializer.validated_data.get('comment', None)
        )
        return Response({'enable': 'ok'})

    @action(detail=True, methods=['post'])
    def disable(self, request, pk):
        category = self.get_object()
        serializer = CategoryChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        category.disable(
            serializer.validated_data['ruleset'], request,
            serializer.validated_data.get('comment', None)
        )
        return Response({'disable': 'ok'})

    def get_serializer_class(self):
        if self.action in ('enable', 'disable'):
            return CategoryChangeSerializer
        return CategorySerializer


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

    class Meta:
        model = Rule
        fields = ('pk', 'sid', 'category', 'msg', 'state', 'state_in_source', 'rev', 'content',
                  'imported_date', 'updated_date', 'created', 'updated', 'hits', 'timeline_data', 'probes')

    def to_representation(self, instance):
        data = super(RuleSerializer, self).to_representation(instance)
        request = self.context['request']
        highlight_str = request.query_params.get('highlight', 'false')

        def is_highlight(value):
            return bool(value) and value.lower() not in ('false', '0')

        highlight = is_highlight(highlight_str)

        if highlight is True:
            data['content'] = SuriHTMLFormat(data['content'])

        return data


class ListFilter(filters.CharFilter):

    def sanitize(self, value_list):
        """
        remove empty items in case of ?number=1,,2
        """
        return [v for v in value_list if v != '']

    def customize(self, value):
        return value

    def filter(self, qs, value):
        multiple_vals = value.split(",")
        multiple_vals = self.sanitize(multiple_vals)
        multiple_vals = list(map(self.customize, multiple_vals))
        for val in multiple_vals:
            qs = super().filter(qs, val)
        return qs


class RuleFilter(filters.FilterSet):
    min_created = filters.DateFilter(field_name="created", lookup_expr='gte')
    max_created = filters.DateFilter(field_name="created", lookup_expr='lte')
    min_updated = filters.DateFilter(field_name="updated", lookup_expr='gte')
    max_updated = filters.DateFilter(field_name="updated", lookup_expr='lte')
    msg = ListFilter(field_name="msg", lookup_expr='icontains')
    not_in_msg = ListFilter(field_name="msg", lookup_expr='icontains', exclude=True)
    content = ListFilter(field_name="content", lookup_expr='icontains')
    not_in_content = ListFilter(field_name="content", lookup_expr='icontains', exclude=True)

    class Meta:
        model = Rule
        fields = ['sid', 'category', 'msg', 'not_in_msg', 'content', 'not_in_content', 'created', 'updated']
        extra_kwargs = {
            'not_in_msg': {'source': 'msg'},
            'not_in_content': {'source': 'content'},
        }


class UserActionFilter(filters.FilterSet):
    min_date = filters.DateFilter(field_name='date', lookup_expr='gte')
    max_date = filters.DateFilter(field_name='date', lookup_expr='lte')
    comment = ListFilter(field_name='comment', lookup_expr='icontains')
    client_ip = filters.CharFilter(field_name='client_ip', lookup_expr='exact')

    class Meta:
        model = UserAction
        fields = ['username', 'date', 'action_type', 'comment', 'client_ip', 'user_action_objects__action_key', 'user_action_objects__action_value']


class RuleHitsOrderingFilter(OrderingFilter):
    def get_query_param(self, request, param):
        value = request.query_params.get(param)
        if value is not None:
            try:
                if ',' in value:
                    values = [int(x) for x in value.split(',')]
                    if param == 'hits_min':
                        return max(values)
                    else:
                        return min(values)

                value = int(value)
            except ValueError:
                value = None
        return value

    def _get_hits_order(self, request, order):
        try:
            result = ESTopRules(request).get(count=Rule.objects.count(), order=order)
        except ESError:
            queryset = Rule.objects.order_by('sid')
            queryset = queryset.annotate(hits=models.Value(0, output_field=models.IntegerField()))
            queryset = queryset.annotate(hits=models.ExpressionWrapper(models.Value(0), output_field=models.IntegerField()))
            return queryset.values_list('sid', 'hits')

        result = [(x['key'], x['doc_count']) for x in result]
        return result

    def _filter_min_max(self, request, queryset, hits_order):
        hits_by_sid = dict(hits_order)

        min_hits = self.get_query_param(request, 'hits_min')
        max_hits = self.get_query_param(request, 'hits_max')
        sids = list(queryset.values_list('sid', flat=True))

        if min_hits is not None or max_hits is not None:
            if min_hits is not None:
                queryset = [sid for sid in sids if hits_by_sid.get(sid, 0) >= min_hits]

            if max_hits is not None:
                queryset = [sid for sid in sids if hits_by_sid.get(sid, 0) <= max_hits]
            return queryset

        return list(queryset.values_list('sid', flat=True))

    def filter_queryset(self, request, queryset, view):
        ordering = self.get_ordering(request, queryset, view)

        if 'hits' in ordering or '-hits' in ordering:
            if ordering[0] not in ('hits', '-hits'):
                raise ParseError('hits ordering can only be the first ordering term')

            hits_ordering = ordering[0]
            ordering = ordering[1:]

            if ordering:
                ordering = tuple(list(ordering) + ['sid'])
                queryset = queryset.order_by(*ordering)

            # Sorting
            order = 'asc' if hits_ordering == 'hits' else 'desc'
            hits_order = self._get_hits_order(request, order)
            rules = self._filter_min_max(request, queryset, hits_order)

            sids = []
            for sid, _ in hits_order:
                if sid in rules:
                    sids.append(sid)
                    rules.remove(sid)

            # We add rules with no hits
            if order == 'desc':
                sids += rules
            else:
                sids = rules + sids

        else:
            if ordering:
                ordering = tuple(list(ordering) + ['sid'])
                queryset = queryset.order_by(*ordering)

            if self.get_query_param(request, 'hits_min') is not None \
                    or self.get_query_param(request, 'hits_max') is not None:
                hits_order = self._get_hits_order(request, 'asc')
                return self._filter_min_max(request, queryset, hits_order)

            sids = list(queryset.values_list('sid', flat=True))

        return sids


class RuleViewSet(SciriusReadOnlyModelViewSet):
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

    Toggle availabililty:\n
        curl -v -k https://x.x.x.x/rest/rules/rule/<sid-rule>/toggle_availability/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"comment": "toggle rule"}'

    Return:\n
        HTTP/1.1 200 OK
        {"toggle_availability":"ok"}

    =============================================================================================================================================================
    """
    queryset = Rule.objects.all()
    serializer_class = RuleSerializer
    ordering = ('sid',)
    ordering_fields = ('sid', 'category', 'msg', 'imported_date', 'updated_date', 'created', 'updated', 'hits')
    filter_backends = (DjangoFilterBackend, RuleHitsOrderingFilter)
    filterset_class = RuleFilter
    REQUIRED_GROUPS = {
        'READ': ('rules.ruleset_policy_view',),
        'WRITE': ('rules.ruleset_policy_edit',),
    }

    def get_permissions(self):
        if self.action == 'delete_alerts':
            if not self.request.user.has_perm('rules.events_edit'):
                return [NoPermission()]
            return [IsAuthenticated()]
        return super().get_permissions()

    @action(detail=True, methods=['get'])
    def references(self, request, pk):
        rule = self.get_object()
        references = extract_rule_references(rule)

        res = []
        for reference in references:
            res.append({'url': reference.url, 'key': reference.key, 'value': reference.value})

        return Response(res)

    @action(detail=True, methods=['post'])
    def delete_alerts(self, request, pk):
        # return 404 error if pk does not exist
        self.get_object()

        if hasattr(Probe.common, 'es_delete_alerts_by_sid'):
            result = Probe.common.es_delete_alerts_by_sid(pk, request=request)
        else:
            errors = ESDeleteAlertsBySid(request).get(pk)
            if errors:
                return Response({'details': '\n'.join(errors)}, status=500)
            return Response({'delete_alerts': 'ok'})
        return Response(result)

    @action(detail=False, methods=['get'])
    def transformation(self, request):
        copy_params = request.query_params.dict()
        key_str = copy_params.pop('transfo_type', None)
        value_str = copy_params.pop('transfo_value', None)

        errors = {}
        if key_str is None:
            errors['transfo_type'] = ['This field is required.']

        if value_str is None:
            errors['transfo_value'] = ['This field is required.']

        if len(errors) > 0:
            raise serializers.ValidationError(errors)

        params = {}
        if key_str:
            params['key'] = key_str
        if value_str:
            params['value'] = value_str

        # Check wrongs filters types (other than type/value)
        if len(copy_params) > 0:
            params_str = ', '.join(list(copy_params.keys()))
            raise serializers.ValidationError({'filters': ['Wrong filters: "%s"' % params_str]})

        # Check key/value filters
        # Key
        if key_str:
            if key_str not in list(Transformation.AVAILABLE_MODEL_TRANSFO.keys()):
                raise serializers.ValidationError({'filters': ['Wrong filter type "%s".' % key_str]})

            # Value
            if value_str and value_str not in Transformation.AVAILABLE_MODEL_TRANSFO[key_str]:
                raise serializers.ValidationError({'filters': ['Wrong filter value "%s" for key "%s".' % (value_str, key_str)]})

        res = {}
        try:
            Rule.enable_cache()

            for ruleset in Ruleset.objects.all():
                trans_rules = RuleTransformation.objects.filter(ruleset=ruleset, **params)
                trans_cats = CategoryTransformation.objects.filter(ruleset=ruleset, **params)
                trans_rulesets = RulesetTransformation.objects.filter(ruleset_transformation=ruleset, **params)

                all_rules = set()
                key = Transformation.Type(key_str)
                value = None

                if key == Transformation.ACTION:
                    value = Transformation.ActionTransfoType(value_str)
                elif key == Transformation.LATERAL:
                    value = Transformation.LateralTransfoType(value_str)
                elif key == Transformation.TARGET:
                    value = Transformation.TargetTransfoType(value_str)

                if ruleset.pk not in res:
                    res[ruleset.pk] = {'name': ruleset.name,
                                       'transformation': {'transfo_key': key_str, 'transfo_value': value_str},
                                       'rules': []
                                       }

                for trans in trans_rules:
                    all_rules.add(trans.rule_transformation.pk)

                for trans in trans_cats:
                    category = trans.category_transformation
                    for rule in category.rule_set.all():
                        rule_trans_value = rule.get_transformation(ruleset, key=key)
                        if rule_trans_value is None or rule_trans_value == value:
                            all_rules.add(rule.sid)

                if trans_rulesets:
                    for category in ruleset.categories.all():
                        trans_cat = CategoryTransformation.objects.filter(ruleset=ruleset, category_transformation=category)

                        if len(trans_cat) == 0:
                            for rule in category.rule_set.all():
                                rule_trans_value = rule.get_transformation(ruleset, key=key)
                                if rule_trans_value is None or rule_trans_value == value:
                                    all_rules.add(rule.sid)
                        else:
                            for trans in trans_cat:
                                for rule in category.rule_set.all():
                                    rule_trans_value = rule.get_transformation(ruleset, key=key)
                                    if trans.key == key and trans.value == value:
                                        if rule_trans_value is None or rule_trans_value == value:
                                            all_rules.add(rule.sid)
                                    else:
                                        if rule_trans_value == value:
                                            all_rules.add(rule.sid)

                res[ruleset.pk]['rules'] = list(all_rules)
                res[ruleset.pk]['rules_count'] = len(all_rules)
        finally:
            Rule.disable_cache()

        return Response(res)

    @action(detail=True, methods=['get'])
    def content(self, request, pk):
        rule = self.get_object()
        rulesets = Ruleset.objects.filter(categories__rule=rule)
        res = {}
        highlight_str = request.query_params.get('highlight', 'false')

        def is_highlight(value):
            return bool(value) and value.lower() not in ('false', '0')

        highlight = is_highlight(highlight_str)

        for ruleset in rulesets:
            content = rule.generate_content(ruleset)
            res[ruleset.pk] = content if not highlight else SuriHTMLFormat(content)

        return Response(res)

    @action(detail=True, methods=['get', 'post'])
    def comment(self, request, pk):
        if request.method == 'POST':
            rule = self.get_object()
            comment = request.data.get('comment', None)

            comment_serializer = CommentSerializer(data={'comment': comment})
            comment_serializer.is_valid(raise_exception=True)

            UserAction.create(
                action_type='comment_rule',
                comment=comment,
                request=request,
                rule=rule
            )
            return Response({'comment': 'ok'})
        elif request.method == 'GET':
            rule = self.get_object()
            uas = rule.get_comments()
            res = {rule.sid: []}
            for ua in uas:
                res[rule.sid].append({'title': ua.get_title(),
                                      'icon': ua.get_icons(),
                                      'comment': ua.comment if len(ua.comment) else 'No comment',
                                      'description': ua.generate_description(request.user),
                                      'date': ua.date})
            return Response(res)

    @action(detail=True, methods=['post'])
    def toggle_availability(self, request, pk):
        rule = self.get_object()
        comment = request.data.get('comment', None)

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        rule.toggle_availability()

        UserAction.create(
            action_type='toggle_availability',
            comment=comment,
            request=request,
            rule=rule
        )

        return Response({'toggle_availability': 'ok'})

    @action(detail=True, methods=['post'])
    def enable(self, request, pk):
        rule = self.get_object()
        serializer = RuleChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rule.enable(
            serializer.validated_data['ruleset'], request,
            serializer.validated_data.get('comment', None)
        )
        return Response({'enable': 'ok'})

    @action(detail=True, methods=['post'])
    def disable(self, request, pk):
        rule = self.get_object()
        serializer = RuleChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rule.disable(
            serializer.validated_data['ruleset'], request,
            serializer.validated_data.get('comment', None)
        )
        return Response({'disable': 'ok'})

    def get_serializer_class(self):
        if self.action in ('enable', 'disable'):
            return RuleChangeSerializer
        return RuleSerializer

    @action(detail=True, methods=['get'])
    def status(self, request, pk):
        rule = self.get_object()

        res = {}
        for ruleset in Ruleset.objects.all():
            res[ruleset.pk] = {}
            res[ruleset.pk]['name'] = ruleset.name
            res[ruleset.pk]['active'] = rule.is_active(ruleset)
            res[ruleset.pk]['valid'] = rule.test(ruleset)

            res[ruleset.pk]['transformations'] = {}
            for key in (Transformation.ACTION, Transformation.LATERAL, Transformation.TARGET):
                trans = rule.get_transformation(key=key, ruleset=ruleset, override=True)
                res[ruleset.pk]['transformations'][key.value] = trans.value if trans else None

        return Response(res)

    def _scirius_hit(self, r):
        timeline = []
        for entry in r['timeline']['buckets']:
            timeline.append({
                'date': entry['key'],
                'hits': entry['doc_count']
            })

        probes = []
        for entry in r['probes']['buckets']:
            probes.append({
                'probe': entry['key'],
                'hits': entry['doc_count']
            })

        return {
            'hits': r['doc_count'],
            'timeline_data': timeline,
            'probes': probes
        }

    def _add_hits(self, request, data):
        sids = ','.join([str(rule['sid']) for rule in data])

        try:
            result = ESSigsListHits(request).get(sids)
        except ESError:
            return data

        # reformat ES's output
        hits = {}
        for r in result:
            hits[r['key']] = self._scirius_hit(r)

        for rule in data:
            sid = rule['sid']
            if sid in hits:
                rule.update(hits[sid])
            else:
                rule.update({
                    'hits': 0,
                    'timeline_data': [],
                    'probes': []
                })
        return data

    def get_object(self):
        sids = self.filter_queryset(self.get_queryset())
        queryset = Rule.objects.filter(sid__in=sids)

        # Perform the lookup filtering.
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field

        assert lookup_url_kwarg in self.kwargs, (
            'Expected view %s to be called with a URL keyword argument '
            'named "%s". Fix your URL conf, or set the `.lookup_field` '
            'attribute on the view correctly.' %
            (self.__class__.__name__, lookup_url_kwarg)
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
    def create(self, request, *args, **kwargs):
        kwargs['fields'] = dict(self._fields)
        kwargs['action_type'] = self._action_type

        comment = request.data.get('comment', None)
        key = request.data.get('transfo_type')
        value = request.data.get('transfo_value')
        trans_ok = key in Transformation.AVAILABLE_MODEL_TRANSFO and value in Transformation.AVAILABLE_MODEL_TRANSFO[key]
        msg = ''

        if trans_ok is False:
            msg = '"%s" is not a valid choice.'
            title = 'transfo_value'
            type_ = value
            values = Transformation.AVAILABLE_MODEL_TRANSFO.get(key, None)

            if values is None:
                title = 'transfo_type'
                type_ = key

            raise serializers.ValidationError({title: [msg % type_]})

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check that transformation is allowed
        if isinstance(self, RuleTransformationViewSet):
            rule = serializer.validated_data['rule_transformation']
            transfo_type = Transformation.Type(key)
            choices_ = rule.get_transformation_choices(transfo_type)
            choices = [choice[0] for choice in choices_]

            if value not in choices:
                raise serializers.ValidationError({'transfo_value': '"%s" is not a valid choice.' % value})

        serializer.save()

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        fields = kwargs['fields']
        for key, value in dict(fields).items():
            fields[key] = serializer.validated_data[value]

        fields['comment'] = comment
        fields['action_type'] = kwargs['action_type']
        fields['user'] = request.user
        fields['transformation'] = '%s: %s' % (fields.pop('trans_type'), fields.pop('trans_value').title())

        UserAction.create(**fields)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        kwargs['fields'] = dict(self._fields)
        kwargs['action_type'] = 'delete_%s' % self._action_type

        instance = self.get_object()
        comment = request.data.get('comment', None)
        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        fields = kwargs['fields']
        for key, value in dict(fields).items():
            fields[key] = getattr(instance, value)

        fields['comment'] = comment
        fields['action_type'] = kwargs['action_type']
        fields['user'] = request.user
        fields['transformation'] = '%s: %s' % (fields.pop('trans_type'), fields.pop('trans_value').title())

        UserAction.create(**fields)
        return super(BaseTransformationViewSet, self).destroy(request, *args, **kwargs)

    def _update_or_partial_update(self, request, partial):
        params = {}
        params['fields'] = dict(self._fields)
        params['action_type'] = self._action_type

        comment = request.data.get('comment', None)
        key = request.data.get('transfo_type')
        value = request.data.get('transfo_value')
        trans_ok = key in Transformation.AVAILABLE_MODEL_TRANSFO and value in Transformation.AVAILABLE_MODEL_TRANSFO[key]
        msg = ''

        if trans_ok is False:
            msg = '"%s" is not a valid choice.'
            title = 'transfo_value'
            type_ = value
            values = Transformation.AVAILABLE_MODEL_TRANSFO.get(key, None)

            if values is None:
                title = 'transfo_type'
                type_ = key
            return trans_ok, title, msg % type_

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.instance.clean()
        serializer.is_valid(raise_exception=True)

        # This save is used to have the new name if user has edited transfo
        serializer.save()

        fields = params['fields']
        for key, value in dict(fields).items():
            if value in serializer.validated_data:
                fields[key] = serializer.validated_data[value]
            else:
                if partial is True:
                    val = getattr(instance, value, None)
                    if val is not None:
                        fields[key] = val

        fields['comment'] = comment_serializer.validated_data['comment']
        fields['action_type'] = params['action_type']
        fields['user'] = request.user
        fields['transformation'] = '%s: %s' % (fields.pop('trans_type'), fields.pop('trans_value').title())

        UserAction.create(**fields)
        return trans_ok, None, None


class RulesetTransformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = RulesetTransformation
        fields = ('pk', 'ruleset', 'transfo_type', 'transfo_value')

        extra_kwargs = {
            'ruleset': {'source': 'ruleset_transformation'},
            'transfo_type': {'source': 'key'},
            'transfo_value': {'source': 'value'},
        }


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
    ordering = ('pk',)
    filterset_fields = ('ruleset_transformation',)
    ordering_fields = ('ruleset_transformation',)
    _fields = {'ruleset': 'ruleset_transformation', 'trans_type': 'key', 'trans_value': 'value'}
    _action_type = 'transform_ruleset'
    REQUIRED_GROUPS = {
        'READ': ('rules.ruleset_policy_view',),
        'WRITE': ('rules.ruleset_policy_edit',),
    }

    def destroy(self, request, *args, **kwargs):
        return super(RulesetTransformationViewSet, self).destroy(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        return super(RulesetTransformationViewSet, self).create(request, *args, **kwargs)

    def update(self, request, pk, *args, **kwargs):
        trans_ok, title, msg = self._update_or_partial_update(request, False)
        if trans_ok is False:
            raise serializers.ValidationError({title: [msg]})
        return super(RulesetTransformationViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        trans_ok, title, msg = self._update_or_partial_update(request, True)
        if trans_ok is False:
            raise serializers.ValidationError({title: [msg]})
        return super(RulesetTransformationViewSet, self).update(request, partial=True, *args, **kwargs)


class CategoryTransformationSerializer(serializers.ModelSerializer):

    class Meta:
        model = CategoryTransformation
        fields = ('pk', 'ruleset', 'category', 'transfo_type', 'transfo_value')
        extra_kwargs = {
            'category': {'source': 'category_transformation'},
            'transfo_type': {'source': 'key'},
            'transfo_value': {'source': 'value'},
        }


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
    ordering = ('pk',)
    filterset_fields = ('category_transformation', 'ruleset')
    ordering_fields = ('pk', 'ruleset', 'category_transformation')
    _fields = {'ruleset': 'ruleset', 'trans_type': 'key', 'trans_value': 'value', 'category': 'category_transformation'}
    _action_type = 'transform_category'
    REQUIRED_GROUPS = {
        'READ': ('rules.ruleset_policy_view',),
        'WRITE': ('rules.ruleset_policy_edit',),
    }

    def destroy(self, request, *args, **kwargs):
        return super(CategoryTransformationViewSet, self).destroy(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        return super(CategoryTransformationViewSet, self).create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        trans_ok, title, msg = self._update_or_partial_update(request, False)
        if trans_ok is False:
            raise serializers.ValidationError({title: [msg]})
        return super(CategoryTransformationViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        trans_ok, title, msg = self._update_or_partial_update(request, True)
        if trans_ok is False:
            raise serializers.ValidationError({title: [msg]})
        return super(CategoryTransformationViewSet, self).update(request, partial=True, *args, **kwargs)


class RuleTransformationSerializer(serializers.ModelSerializer):

    class Meta:
        model = RuleTransformation
        fields = ('pk', 'ruleset', 'rule', 'transfo_type', 'transfo_value')
        extra_kwargs = {
            'rule': {'source': 'rule_transformation'},
            'transfo_type': {'source': 'key'},
            'transfo_value': {'source': 'value'},
        }


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
    ordering = ('pk',)
    filterset_fields = ('rule_transformation', 'ruleset')
    ordering_fields = ('pk', 'ruleset', 'rule_transformation')
    _fields = {'ruleset': 'ruleset', 'trans_type': 'key', 'trans_value': 'value', 'rule': 'rule_transformation'}
    _action_type = 'transform_rule'
    REQUIRED_GROUPS = {
        'READ': ('rules.ruleset_policy_view',),
        'WRITE': ('rules.ruleset_policy_edit',),
    }

    def destroy(self, request, *args, **kwargs):
        return super(RuleTransformationViewSet, self).destroy(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        return super(RuleTransformationViewSet, self).create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        trans_ok, title, msg = self._update_or_partial_update(request, False)
        if trans_ok is False:
            raise serializers.ValidationError({title: [msg]})
        return super(RuleTransformationViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        trans_ok, title, msg = self._update_or_partial_update(request, True)
        if trans_ok is False:
            raise serializers.ValidationError({title: [msg]})
        return super(RuleTransformationViewSet, self).update(request, partial=True, *args, **kwargs)


class BaseSourceSerializer(serializers.ModelSerializer):
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True, allow_null=True)

    class Meta:
        model = Source
        fields = ('pk', 'name', 'created_date', 'updated_date', 'method', 'datatype', 'uri', 'cert_verif',
                  'cats_count', 'rules_count', 'use_iprep', 'version', 'use_sys_proxy')
        read_only_fields = ('pk', 'created_date', 'updated_date', 'method', 'datatype', 'cert_verif',
                            'cats_count', 'rules_count',)

    def create(self, validated_data):
        validated_data['created_date'] = timezone.now()
        validated_data['updated_date'] = timezone.now()
        validated_data['cert_verif'] = True
        instance = super(BaseSourceSerializer, self).create(validated_data)
        SourceAtVersion.objects.create(source=instance, version='HEAD')
        return instance


class BaseSourceViewSet(viewsets.ModelViewSet):
    REQUIRED_GROUPS = {
        'READ': ('rules.source_view',),
        'WRITE': ('rules.source_edit',),
    }

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        comment = data.pop('comment', None)

        # because of rest website UI
        if isinstance(comment, list):
            comment = comment[0]

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)
        source = serializer.instance

        UserAction.create(
            action_type='create_source',
            comment=comment_serializer.validated_data['comment'],
            request=request,
            source=source
        )

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        source = self.get_object()
        # Do not need to copy 'request.data' and pop 'comment'
        # because we are not using serializer there
        comment = request.data.get('comment', None)
        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
            action_type='delete_source',
            request=request,
            source=source,
            comment=comment_serializer.validated_data['comment']
        )
        return super(BaseSourceViewSet, self).destroy(request, *args, **kwargs)

    def upload(self, request, pk):
        source = self.get_object()

        comment_serializer = CommentSerializer(data=request.data)
        comment_serializer.is_valid(raise_exception=True)

        if source.method != 'local':
            msg = 'No upload is allowed. method is currently "%s"' % source.method
            raise serializers.ValidationError({'upload': [msg]})

        if 'file' not in request.FILES:
            raise serializers.ValidationError({'file': ['This field is required.']})

        try:
            source.new_uploaded_file(request.FILES['file'])
        except Exception as error:
            raise serializers.ValidationError({'upload': [str(error)]})

        UserAction.create(
            action_type='upload_source',
            comment=comment_serializer.validated_data.get('comment'),
            request=request,
            source=source
        )

        return Response({'upload': 'ok'}, status=200)

    @action(detail=True, methods=['post'])
    def update_source(self, request, pk):
        # Do not need to copy 'request.data' and pop 'comment'
        # because we are not using serializer there
        comment = request.data.get('comment', None)
        is_async_str = request.query_params.get('async', 'false')

        def is_async(value):
            return bool(value) and value.lower() not in ('false', '0')

        async_ = is_async(is_async_str)

        source = self.get_object()
        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        try:
            msg = 'ok'
            if async_ is True:
                if hasattr(Probe.common, 'update_source_rest'):
                    Probe.common.update_source_rest(request, source)
                else:
                    raise ServiceUnavailableException()
            else:
                source.update()
        except Exception as errors:
            if isinstance(errors, (IOError, OSError)):
                msg = 'Can not fetch data'
            elif isinstance(errors, ValidationError):
                msg = 'Source is invalid'
            elif isinstance(errors, SuspiciousOperation):
                msg = 'Source is not correct'
            else:
                msg = 'Error updating source'
            msg = '%s: %s' % (msg, errors)
            raise serializers.ValidationError({'update': [msg]})

        UserAction.create(
            action_type='update_source',
            comment=comment_serializer.validated_data['comment'],
            request=request,
            source=source
        )
        return Response({'update': msg})

    @action(detail=False, methods=['get'])
    def list_sources(self, request):
        try:
            public_sources = get_public_sources(False)
        except Exception as e:
            raise serializers.ValidationError({'list': [str(e)]})
        return Response(public_sources['sources'])

    @action(detail=False, methods=['get'])
    def fetch_list_sources(self, request):
        try:
            fetch_public_sources()
        except Exception as e:
            raise serializers.ValidationError({'fetch': [str(e)]})
        return Response({'fetch': 'ok'})

    @action(detail=True, methods=['post'])
    def test(self, request, pk):
        source = self.get_object()
        sources_at_version = SourceAtVersion.objects.filter(source=source, version='HEAD')
        res = sources_at_version[0].test()

        if ('status' not in res or res['status'] is False) or \
                ('errors' not in res or len(res['errors']) > 0):
            raise serializers.ValidationError({'test': {'errors': res['errors']}})

        response = {'test': 'ok'}
        if 'warnings' in res and len(res['warnings']) > 0:
            response['warnings'] = res['warnings']

        return Response(response)

    @action(detail=True, methods=['post'])
    def build_counter(self, request, pk):
        instance = self.get_object()
        instance.build_counters()
        return Response({'build_counter': 'ok'})


class PublicSourceSerializer(BaseSourceSerializer):
    public_source = serializers.CharField(required=True)
    secret_code = serializers.CharField(required=False)

    class Meta(BaseSourceSerializer.Meta):
        model = BaseSourceSerializer.Meta.model
        fields = BaseSourceSerializer.Meta.fields + ('public_source', 'secret_code', 'comment')
        read_only_fields = BaseSourceSerializer.Meta.read_only_fields + ('public_source', 'uri')

    def create(self, validated_data):
        source_name = validated_data['public_source']

        try:
            public_sources = get_public_sources(False)
        except Exception as e:
            raise serializers.ValidationError({'list': [str(e)]})

        if source_name not in public_sources['sources']:
            raise exceptions.NotFound(detail='Unknown public source "%s"' % source_name)

        uri = public_sources['sources'][source_name]['url']
        if 'secret-code' not in uri:
            if 'secret_code' in validated_data:
                raise serializers.ValidationError({'secret_code': ['No secret code needed']})
        else:
            if 'secret_code' not in validated_data:
                raise serializers.ValidationError({'secret_code': ['Secret code is needed']})
            uri = uri % {'secret-code': validated_data.pop('secret_code')}

        uri = uri % {'__version__': '5.0'}

        validated_data['uri'] = uri
        validated_data['datatype'] = public_sources['sources'][source_name]['datatype']
        validated_data['method'] = 'http'
        validated_data['public_source'] = source_name
        instance = super(PublicSourceSerializer, self).create(validated_data)

        return instance


class PublicSourceViewSet(BaseSourceViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    List all used sources: (if cats_count == 0 and/or rules_count == 0 call update_source THEN build_counter api)\n
        curl -k https://x.x.x.x/rest/rules/public_source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":1,"name":"Source1","created_date":"2018-05-04T10:15:46.216023+02:00","updated_date":"2018-05-04T15:22:15.267123+02:00","method":"http","datatype":"sigs","uri":"https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz","cert_verif":true,"cats_count":47,"rules_count":25490}

    List available public sources:\n
        curl -k https://x.x.x.x/rest/rules/public_source/list_sources/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"oisf/trafficid":{"support_url":"https://redmine.openinfosecfoundation.org/","added":true,"vendor":"OISF","datatype":"sig","license":"MIT","url":"https://raw.githubusercontent.com/jasonish/suricata-trafficid/master/rules/traffic-id.rules","support_url_cleaned":"https://redmine.openinfosecfoundation.org/","min_version":"4.0.0","summary":"Suricata Traffic ID ruleset"},
        ....
        "sslbl/ssl-fp-blacklist":{"added":false,"vendor":"Abuse.ch","license":"Non-Commercial","url":"https://sslbl.abuse.ch/blacklist/sslblacklist.rules","summary":"Abuse.ch SSL Blacklist","datatype":"sig"},
        "et/open":{"added":false,"vendor":"Proofpoint","license":"MIT","url":"https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz","summary":"Emerging Threats Open Ruleset","datatype":"sigs"},
        ....
        "et/pro":{"replaces":["et/open"],"vendor":"Proofpoint","description":"Proofpoint ET Pro is a timely and accurate rule set for detecting and blocking advanced threats","license":"Commercial","subscribe_url":"https://www.proofpoint.com/us/threat-insight/et-pro-ruleset","url":"https://rules.emergingthreatspro.com/%(secret-code)s/suricata-%(__version__)s/etpro.rules.tar.gz","summary":"Emerging Threats Pro Ruleset","subscribe_url_cleaned":"https://www.proofpoint.com/us/threat-insight/et-pro-ruleset","datatype":"sigs","added":false,"parameters":{"secret_code":{"prompt":"Emerging Threats Pro access code"}}}}

    Fetch sources list:\n
        curl -k https://x.x.x.x/rest/rules/public_source/fetch_list_sources/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"fetch":"ok"}

    ==== POST ====\n
    Create public source:\n
        curl -k https://x.x.x.x/rest/rules/public_source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"name": "sonic public source", "public_source": "oisf/trafficid"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":4,"name":"sonic public source","created_date":"2018-05-07T11:54:56.450782+02:00","updated_date":"2018-05-07T11:54:56.450791+02:00","method":"http","datatype":"sig","uri":"https://raw.githubusercontent.com/jasonish/suricata-trafficid/master/rules/traffic-id.rules","cert_verif":true,"cats_count":0,"rules_count":0,"public_source":"oisf/trafficid"}

    Update public source:\n
        curl -k https://x.x.x.x/rest/rules/public_source/<pk-public-source>/update_source/?async=true -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

        curl -k https://x.x.x.x/rest/rules/public_source/<pk-public-source>/update_source/?async=false -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"update":"ok"}

    Test public source:\n
        curl -k https://x.x.x.x/rest/rules/public_source/<pk-public-source>/test/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"test":"ok"}

    ==== DELETE ====\n
    Delete public source:\n
        curl -k https://x.x.x.x/rest/rules/public_source/<pk-public-source>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """
    queryset = Source.objects.all()
    serializer_class = PublicSourceSerializer
    ordering = ('name',)
    ordering_fields = ('name', 'created_date', 'updated_date', 'cats_count', 'rules_count',)
    filterset_fields = ('name', 'method')
    search_fields = ('name', 'method')


class SourceSerializer(BaseSourceSerializer):
    datatype = serializers.ChoiceField(required=True, choices=Source.CONTENT_TYPE)
    method = serializers.ChoiceField(required=True, choices=Source.FETCH_METHOD)

    class Meta(BaseSourceSerializer.Meta):
        model = BaseSourceSerializer.Meta.model
        fields = BaseSourceSerializer.Meta.fields + ('method', 'uri', 'authkey', 'comment')
        read_only_fields = BaseSourceSerializer.Meta.read_only_fields

    def create(self, validated_data):
        validated_data['public_source'] = None
        instance = super(SourceSerializer, self).create(validated_data)
        return instance


class SourceViewSet(BaseSourceViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    List all used sources:\n
    List all used sources: (if cats_count == 0 and/or rules_count == 0 call update_source (if method==http) THEN build_counter api)\n
        curl -k https://x.x.x.x/rest/rules/source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":1,"name":"Source1","created_date":"2018-05-04T10:15:46.216023+02:00","updated_date":"2018-05-04T15:22:15.267123+02:00","method":"http","datatype":"sigs","uri":"https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz","cert_verif":true,"cats_count":47,"rules_count":25490,"authkey":"123456789"}

    ==== POST ====\n
    Create custom source:\n
        curl -k https://x.x.x.x/rest/rules/source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"name": "sonic custom source", "method": "local", "datatype": "sigs", "use_sys_proxy": true}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":5,"name":"sonic Custom source","created_date":"2018-05-07T12:01:00.658118+02:00","updated_date":"2018-05-07T12:01:00.658126+02:00","method":"local","datatype":"sigs","uri":null,"cert_verif":true,"cats_count":0,"rules_count":0,"authkey":"123456789","use_sys_proxy":true}

    Update custom (only for {method: http}):\n
        curl -k "https://x.x.x.x/rest/rules/source/<pk-source>/update_source/?async=true" -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

        curl -k "https://x.x.x.x/rest/rules/source/<pk-source>/update_source/?async=false" -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"update":"ok"}

    Test custom source:\n
        curl -k https://x.x.x.x/rest/rules/source/<pk-source>/test/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"test":"ok"}

    Upload rules (only for {method: local}):\n
        curl -k https://x.x.x.x/rest/rules/source/<pk-source>/upload/ -H 'Authorization: Token <token>' --keepalive-time 20 -F file=@/tmp/emerging.rules.tar.gz  -X POST

    Return:\n
        HTTP/1.1 100 Continue
        HTTP/1.1 200 OK
        {"upload":"ok"}

    ==== DELETE ====\n
    Delete custom source:\n
        curl -k https://x.x.x.x/rest/rules/source/<pk-source>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """
    queryset = Source.objects.all()
    serializer_class = SourceSerializer
    parser_classes = (MultiPartParser, JSONParser)
    ordering = ('name',)
    ordering_fields = ('name', 'created_date', 'updated_date', 'cats_count', 'rules_count', 'datatype')
    filterset_fields = ('name', 'method', 'datatype')
    search_fields = ('name', 'method', 'datatype')

    @action(detail=True, methods=['post'])
    def upload(self, request, pk):
        return super(SourceViewSet, self).upload(request, pk)


class UserActionSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserAction
        fields = ('pk', 'action_type', 'date', 'comment', 'user', 'username', 'ua_objects', 'client_ip')

    def to_representation(self, instance):
        from scirius.utils import get_middleware_module
        data = super(UserActionSerializer, self).to_representation(instance)
        actions_dict = get_middleware_module('common').get_user_actions_dict()

        all_content = {}
        format_ = {'user': instance.username, 'datetime': instance.date}
        for ua_obj in UserActionObject.objects.filter(user_action=instance):
            content = {}

            # build description
            format_[ua_obj.action_key] = ua_obj.action_value

            # Transformation has None type
            if ua_obj.content_type is not None:
                klass = ua_obj.content_type.model_class()
                content['type'] = klass.__name__

                # Check existance of content_object
                sub_instances = klass.objects.filter(pk=ua_obj.object_id)
                if len(sub_instances) > 0:
                    if klass.__name__ != 'Rule':
                        content['pk'] = ua_obj.object_id
                    else:
                        content['sid'] = ua_obj.object_id

            content['value'] = ua_obj.action_value
            all_content[ua_obj.action_key] = content

        data['title'] = instance.get_title()
        data['description_raw'] = actions_dict[instance.action_type]['description'] if instance.action_type is not None else None
        data['description'] = actions_dict[instance.action_type]['description'].format(**format_) if instance.description is None else instance.description
        data['ua_objects'] = all_content

        return data


class UserActionDateOrderingFilter(OrderingFilter):
    def filter_queryset(self, request, queryset, view):
        ordering = self.get_ordering(request, queryset, view)

        if 'date' not in ordering or '-date' not in ordering:
            ordering += ('-date',) if isinstance(ordering, tuple) else ['-date']
        return queryset.order_by(*ordering)


class UserActionViewSet(SciriusReadOnlyModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show an user action :\n
        curl -k https://x.x.x.x/rest/rules/history/<pk-useraction>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"id":612,"action_type":"disable_category","date":"2018-05-14T16:13:24.711372+02:00","comment":null,"username":"scirius",
        "description":"scirius has disabled category emerging-scada in ruleset SonicRulesetOther","user":1,"title":"Disable Category",
        "description_raw":"{user} has disabled category {category} in ruleset {ruleset}","ua_objects":{"category":{"pk":147,"type":"Category","value":"emerging-scada"},
        "ruleset":{"pk":65,"type":"Ruleset","value":"SonicRulesetOther"}}}

    Ordering by username ASC:\n
        curl -k "https://x.x.x.x/rest/rules/history/?ordering=username" -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Ordering by username DESC:\n
        curl -k "https://x.x.x.x/rest/rules/history/?ordering=-username" -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Filtering by username and action_type:\n
        curl -k "https://x.x.x.x/rest/rules/history/?date=&username=scirius&user_action_objects__action_key=&action_type=edit_ruleset" -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Ordering & Filtering:\n
        curl -k "https://x.x.x.x/rest/rules/history/?action_type=edit_ruleset&date=&ordering=username&user_action_objects__action_key=&username=scirius" -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Get list of action type:\n
        curl -k https://x.x.x.x/rest/rules/history/get_action_type_list/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"action_type_list":{"create_appliance":"Create Appliance","delete_alerts":"Delete Alerts","delete_threshold":"Delete Threshold","transform_ruleset":"Transform Ruleset","create_source":"Create Source",
        "comment_rule":"Comment Rule","enable_category":"Enable Category","delete_ruleset":"Delete Ruleset","system_settings":"Edit System Settings","toggle_availability":"Toggle Availability","login":"Login",
        "edit_suricata":"Edit Suricata","delete_transform_category":"Delete Category Transformation","delete_transform_ruleset":"Deleted Ruleset Transformation","delete_transform_rule":"Delete Rule Transformation",
        "create_network_def":"Create Network Definition","create_threshold":"Create Threshold","edit_threshold":"Edit Threshold","delete_network_def":"Delete Network Definition","create_ruleset":"Create Ruleset",
        "transform_category":"Transform Category","transform_rule":"Transform Rule","edit_rule_filter":"Edit rule filter","update_source":"Update Source","upload_source":"Upload Source","suppress_rule":"Suppress Rule",
        "create_template":"Create Template","delete_suppress_rule":"Delete Suppress Rule","edit_source":"Edit Source","logout":"Logout","delete_appliance":"Delete Appliance","delete_template":"Delete Template",
        "edit_appliance":"Edit Appliance","edit_template":"Edit Template","create_suricata":"Create Suricata","disable_category":"Disable Category","disable_rule":"Disable Rule","enable_source":"Enable Source",
        "edit_network_def":"Edit Network Definition","delete_source":"Delete Source","enable_rule":"Enable Rule","disable_source":"Disable Source","edit_ruleset":"Edit Ruleset","delete_rule_filter":"Delete rule filter",
        "import_network_def":"Import Network Definition","copy_ruleset":"Copy Ruleset","create_rule_filter":"Create rule filter"}}

    =============================================================================================================================================================
    """

    queryset = UserAction.objects.all()
    serializer_class = UserActionSerializer
    ordering = ('-pk',)
    ordering_fields = ('pk', 'date', 'username', 'action_type', 'client_ip')
    filter_class = UserActionFilter
    filter_backends = (filters.DjangoFilterBackend, UserActionDateOrderingFilter)
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        actions_type = UserAction.get_allowed_actions_type(self.request)
        history = UserAction.objects.filter(action_type__in=actions_type)
        user = self.request.user
        if user.__class__.__name__ != 'FakeUser':
            history |= UserAction.objects.filter(user=user)
        return history

    @action(detail=False, methods=['get'])
    def get_action_type_list(self, request):
        from scirius.utils import get_middleware_module
        actions_dict = get_middleware_module('common').get_user_actions_dict()

        res = OrderedDict()
        for key, value in actions_dict.items():
            res.update({key: value['title']})

        return Response({'action_type_list': res})


class ChangelogSerializer(serializers.ModelSerializer):
    class Meta:
        model = SourceUpdate
        fields = ('pk', 'source', 'created_date', 'data', 'version', 'changed',)

    def to_representation(self, instance):
        data = super(ChangelogSerializer, self).to_representation(instance)
        data['data'] = instance.diff()
        return data


class ChangelogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    =============================================================================================================================================================
    Show all Changelogs from all sources:\n
        curl -k https://x.x.x.x/rest/rules/changelog/source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"count":4,"next":null,"previous":null,"results":[{"pk":1,"source":1,"created_date":"2018-07-03T15:20:59.168931Z","data":{"deleted":[],"date":"2018-07-03T15:20:59.168931Z",
        "updated":[{"msg":"SURICATA TRAFFIC-ID: Debian APT-GET","category":"Suricata Traffic ID ruleset Sigs","sid":300000032,"pk":300000032},
        {"msg":"SURICATA TRAFFIC-ID: Ubuntu APT-GET","category":"Suricata Traffic ID ruleset Sigs","sid":300000033,"pk":300000033}],"added":[],"stats":{"deleted":0,"updated":2,"added":0}},
        "version":"9b73cdc0e25b36ce3a80fdcced631f3769a4f6f6","changed":2},{"pk":2,"source":2,"created_date":"2018-07-03T15:25:24.449902Z","data":{"deleted":[],
        "date":"2018-07-03T15:25:24.449902Z","updated":[],"added":[],"stats":{"deleted":0,"updated":0,"added":0}},"version":"fbae31b8d3a12e1d603e8ce64e7ae0f4f0cff130","changed":0},
        {"pk":3,"source":1,"created_date":"2018-07-03T15:25:25.376499Z","data":{"deleted":[],"date":"2018-07-03T15:25:25.376499Z","updated":[{"msg":"SURICATA TRAFFIC-ID: Debian APT-GET",
        "category":"Suricata Traffic ID ruleset Sigs","sid":300000032,"pk":300000032},{"msg":"SURICATA TRAFFIC-ID: Ubuntu APT-GET","category":"Suricata Traffic ID ruleset Sigs","sid":300000033,
        "pk":300000033}],"added":[],"stats":{"deleted":0,"updated":2,"added":0}},"version":"9b73cdc0e25b36ce3a80fdcced631f3769a4f6f6","changed":2},{"pk":4,"source":1,"created_date":"2018-07-03T17:14:02.359963Z",
        "data":{"deleted":[],"date":"2018-07-03T17:14:02.359963Z","updated":[{"msg":"SURICATA TRAFFIC-ID: Debian APT-GET","category":"Suricata Traffic ID ruleset Sigs","sid":300000032,"pk":300000032},
        {"msg":"SURICATA TRAFFIC-ID: Ubuntu APT-GET","category":"Suricata Traffic ID ruleset Sigs","sid":300000033,"pk":300000033}],"added":[],"stats":{"deleted":0,"updated":2,"added":0}},
        "version":"9b73cdc0e25b36ce3a80fdcced631f3769a4f6f6","changed":2}]}

    Show changelogs filter by source:\n
        curl -k https://x.x.x.x/rest/rules/changelog/source/?source=2 -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Show changelogs filter by version:\n
        curl -k https://x.x.x.x/rest/rules/changelog/source/?version=9b73cdc0e25b36ce3a80fdcced631f3769a4f6f6 -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    =============================================================================================================================================================
    """
    serializer_class = ChangelogSerializer
    queryset = SourceUpdate.objects.all()
    filterset_fields = ('source', 'version')
    ordering = ('-pk',)
    ordering_fields = ('pk', 'source', 'version',)
    REQUIRED_GROUPS = {
        'READ': ('rules.source_view',),
    }


class ESBaseViewSet(APIView):
    """
    ES Abstract Base class
    """

    def get(self, request, format=None):
        try:
            return self._get(request, format)
        except ESError as e:
            return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _get(self, request, format):
        raise NotImplementedError('This is an abstract class. ES sub classes must override this method')


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
        'READ': ('rules.configuration_view', 'rules.events_view'),
    }

    def _get(self, request, format=None):
        errors = {}
        if 'hosts' not in request.GET:
            errors['hosts'] = ['This field is required.']

        if len(errors) > 0:
            raise serializers.ValidationError(errors)

        return Response({'rules': ESRulesStats(request).get(dict_format=True)})


class ESRuleViewSet(ESBaseViewSet):
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
        'READ': ('rules.configuration_view', 'rules.events_view'),
    }

    def _get(self, request, format=None):
        sid = request.GET.get('sid', None)

        errors = {}
        if sid is None:
            errors['sid'] = ['This field is required.']

        if len(errors) > 0:
            raise serializers.ValidationError(errors)

        return Response({'rule': ESSidByHosts(request).get(sid, dict_format=True)})


class ESTopRulesViewSet(ESBaseViewSet):
    """
    """
    REQUIRED_GROUPS = {
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        count = request.GET.get('count', 20)
        order = request.GET.get('order', "desc")

        if 'hosts' not in request.GET:
            errors = {'hosts': ['This field is required.']}
            raise serializers.ValidationError(errors)

        return Response(ESTopRules(request).get(count=count, order=order))


class ESSigsListViewSet(ESBaseViewSet):
    """
    """
    REQUIRED_GROUPS = {
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        sids = request.GET.get('sids', 20)

        errors = {}
        if sids is None:
            errors['sids'] = ['This field is required.']

        if 'hosts' not in request.GET:
            errors['hosts'] = ['This field is required.']

        if len(errors) > 0:
            raise serializers.ValidationError(errors)

        return Response(ESSigsListHits(request).get(sids))


class ESPostStatsViewSet(ESBaseViewSet):
    """
    """
    REQUIRED_GROUPS = {
        'READ': ('rules.ruleset_policy_view',),
    }

    def _get(self, request, format=None):
        value = request.GET.get('value', None)
        return Response(ESPoststats(request).get(value=value))


class ESFieldsStatsViewSet(ESBaseViewSet):
    """
    """
    REQUIRED_GROUPS = {
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        errors = {}
        fields = request.GET.get('fields', None)
        sid = request.GET.get('sid', None)

        if fields is None:
            errors = {'fields': ['This field is required.']}
            raise serializers.ValidationError(errors)

        count = request.GET.get('page_size', 10)

        field_list = fields.split(',')
        tmpl_fields = []
        for field in field_list:
            if field not in ['src_port', 'dest_port', 'alert.signature_id', 'alert.severity', 'http.length', 'http.status', 'vlan', 'geoip.provider.autonomous_system_number', 'tunnel.depth']:
                tmpl_fields.append({'name': field, 'key': field + '.' + settings.ELASTICSEARCH_KEYWORD})
            else:
                tmpl_fields.append({'name': field, 'key': field})

        values = ESFieldsStats(request).get(
            sid,
            tmpl_fields,
            count=count,
            dict_format=True
        )

        return Response(values)


class ESFieldStatsViewSet(ESBaseViewSet):
    """
    """
    REQUIRED_GROUPS = {
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        errors = {}
        field = request.GET.get('field', None)
        sid = request.GET.get('sid', None)

        if field is None:
            errors = {'field': ['This field is required.']}
            raise serializers.ValidationError(errors)

        filter_ip = request.GET.get('field', 'src_ip')
        count = request.GET.get('page_size', 10)

        if filter_ip not in ['src_port', 'dest_port', 'alert.signature_id', 'alert.severity', 'http.length', 'http.status', 'vlan', 'geoip.provider.autonomous_system_number', 'tunnel.depth']:
            filter_ip = filter_ip + '.' + settings.ELASTICSEARCH_KEYWORD

        hosts = ESFieldStats(request).get(
            sid,
            filter_ip,
            count=count,
            dict_format=True
        )

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
        'READ': ('rules.events_view',),
    }

    RULE_FIELDS_MAPPING = {'rule_src': 'src_ip', 'rule_dest': 'dest_ip', 'rule_source': 'alert.source.ip', 'rule_target': 'alert.target.ip'}

    def _get(self, request, format=None):
        errors = {}
        field = request.GET.get('field', None)
        sid = request.GET.get('sid', None)

        if field is None:
            errors['field'] = ['This field is required.']
            raise serializers.ValidationError(errors)

        if field not in list(self.RULE_FIELDS_MAPPING.keys()):
            raise exceptions.NotFound(detail='"%s" is not a valid field' % field)

        filter_ip = self.RULE_FIELDS_MAPPING[field]
        count = request.GET.get('page_size', 10)

        hosts = ESFieldStats(request).get(
            sid,
            filter_ip + '.' + settings.ELASTICSEARCH_KEYWORD,
            count=count,
            dict_format=True
        )

        return Response(hosts)


class ESTimelineViewSet(ESBaseViewSet):
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
        'READ': ('rules.configuration_view', 'rules.events_view'),
    }
    no_tenant_check = True

    def _get(self, request, format=None):
        tags = False if request.GET.get('target', 'false') == 'false' else True

        if request.user.has_perm('rules.events_view') and not request.user.has_perm('rules.configuration_view') and not tags:
            raise PermissionDenied()

        if not request.user.has_perm('rules.events_view') and request.user.has_perm('rules.configuration_view') and tags:
            raise PermissionDenied()

        return Response(ESTimeline(request).get(tags=tags))


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
        'READ': ('rules.configuration_view',),
    }

    def _get(self, request, format=None):
        value = request.GET.get('value', None)
        hosts = self.request.GET.get('hosts', 'global')
        hosts = hosts.split(',')

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
        'READ': ('rules.configuration_view',),
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
        'READ': ('rules.configuration_view',),
    }

    def _get(self, request, format=None):
        return Response(ESStats(request).get())


class ESShardStatsViewSet(ESBaseViewSet):
    REQUIRED_GROUPS = {
        'READ': ('rules.configuration_view',),
    }

    def _get(self, request, format=None):
        return Response(ESShardStats(request).get())


class ESCheckVersionViewSet(APIView):
    """
    """
    REQUIRED_GROUPS = {
        'WRITE': ('rules.configuration_view',),
    }

    def post(self, request, format=None):
        from scirius.utils import get_middleware_module
        res = {}
        try:
            es_url = self.request.data.get('es_url', '')
            es_user = self.request.data.get('es_user', '')
            es_pass = self.request.data.get('es_pass', '')

            es_url = build_es_url(es_url, es_user, es_pass)
            res = get_middleware_module('common').check_es_version(request, es_url)
        except (ValueError, ValidationError) as error:
            res['error'] = 'Invalid hostname or IP, %s' % error
        return Response(res)


class ESRulesPerCategoryViewSet(ESBaseViewSet):
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
        'READ': ('rules.ruleset_policy_view',),
    }

    def _get(self, request, format=None):
        return Response(ESRulesPerCategory(request).get())


class ESAlertsCountViewSet(ESBaseViewSet):
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
        'READ': ('rules.events_view', 'rules.configuration_view'),
    }
    no_tenant_check = True

    def _get(self, request, format=None):
        if request.GET.get('prev') != 'false':
            data = ESAlertsTrend(request).get()
        else:
            data = ESAlertsCount(request).get()
        return Response(data)


class ESTimeRangeAllAlertsViewSet(ESBaseViewSet):
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
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        data = ESTimeRangeAllAlerts(request).get()
        # ceil to 1 sec while we can loose alerts if not celing
        # timestamp has been truncated by frontend
        data['max_timestamp'] = data['max_timestamp'] + 1000
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
        'READ': ('rules.configuration_view',),
    }

    def _get(self, request, format=None):
        return Response(ESLatestStats(request).get())


class ESIPPairAlertsViewSet(ESBaseViewSet):
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
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        return Response(ESIppairAlerts(request).get())


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
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        return Response(ESIppairNetworkAlerts(request).get())


class ESAlertsTailViewSet(ESBaseViewSet):
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
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        pagination = ESPaginator(request)
        es_params = pagination.get_es_params(self)
        ordering = request.query_params.get('ordering', None)

        if not pagination.validate_ordering(ordering):
            return Response("Wrong ordering value: %s" % ordering, status=status.HTTP_400_BAD_REQUEST)

        index = settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX + '*'
        data = ESEventsTail(request, index).get(es_params=es_params, ordering=ordering is not None, event_type='alert')
        res = pagination.get_paginated(data)
        return Response(res)


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
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        pagination = ESPaginator(request)
        es_params = pagination.get_es_params(self)
        ordering = request.query_params.get('ordering', None)

        if not pagination.validate_ordering(ordering):
            return Response("Wrong ordering value: %s" % ordering, status=status.HTTP_400_BAD_REQUEST)

        index = settings.ELASTICSEARCH_LOGSTASH_INDEX + '*'
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
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        pagination = ESPaginator(request)
        es_params = pagination.get_es_params(self)
        ordering = request.query_params.get('ordering', None)

        if not pagination.validate_ordering(ordering):
            return Response("Wrong ordering value: %s" % ordering, status=status.HTTP_400_BAD_REQUEST)

        index = settings.ELASTICSEARCH_LOGSTASH_INDEX + 'tls-*'
        data = ESEventsTail(request, index).get(es_params=es_params, ordering=ordering is not None, event_type='tls')
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
        'READ': ('rules.events_view',),
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
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        ip = request.GET.get('ip', None)
        if ip is None:
            raise serializers.ValidationError({'ip': ['This field is required']})

        src_ip_res = ESIPFlowTimeline(request).get(target='src_ip', ip=ip)
        dest_ip_res = ESIPFlowTimeline(request).get(target='dest_ip', ip=ip)

        for idx, item in enumerate(src_ip_res.get('aggregations', {}).get('date', {}).get('buckets', [])):
            item.pop('doc_count')
            item['rx_bytes']['value'] += dest_ip_res['aggregations']['date']['buckets'][idx]['tx_bytes']['value']
            item['tx_bytes']['value'] += dest_ip_res['aggregations']['date']['buckets'][idx]['rx_bytes']['value']

        return Response(src_ip_res)


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
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None):
        return Response(ESEventsTimeline(request).get())


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
        'READ': ('rules.events_view',),
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
        'READ': ('rules.configuration_view',),
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
        'WRITE': ('rules.configuration_edit',),
    }

    def post(self, request, format=None):
        es_data = ESData()
        msg = None

        try:
            es_data.es_clear()
        except ConnectionError:
            msg = 'Could not connect to Elasticsearch'
        except Exception as e:
            msg = 'Clearing failed: %s' % e

        if msg is not None:
            raise serializers.ValidationError({'delete_es_logs': [msg]})

        return Response({'delete_es_logs': 'ok'})


class SystemSettingsSerializer(serializers.ModelSerializer):
    def to_representation(self, data):
        data = super().to_representation(data)
        data.pop('elasticsearch_pass')
        return data

    class Meta:
        model = SystemSettings
        fields = '__all__'
        read_only_fields = ('kibana', 'kibana_url', 'evebox', 'evebox_url', 'cyberchef', 'cyberchef_url')


class SystemSettingsViewSet(UpdateModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show system settings:\n
        curl -k https://x.x.x.x/rest/rules/system_settings/1/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    ==== PUT/PATCH ====\n
        curl -k https://x.x.x.x/rest/rules/system_settings/1/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"use_http_proxy":false,"http_proxy":"","https_proxy":"","use_elasticsearch":true,"custom_elasticsearch":false,"elasticsearch_url":"http://elasticsearch:9200/"}'
        curl -k https://x.x.x.x/rest/rules/system_settings/1/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"use_http_proxy":false,"http_proxy":"","https_proxy":"","use_elasticsearch":true,"custom_elasticsearch":false,"elasticsearch_url":"http://elasticsearch:9200/"}'

    Return:\n
        HTTP/1.1 200 OK
        {"id":1,"use_http_proxy":false,"http_proxy":"","https_proxy":"","use_elasticsearch":true,"custom_elasticsearch":false,"elasticsearch_url":"http://elasticsearch:9200/"}

    =============================================================================================================================================================
    """
    serializer_class = SystemSettingsSerializer
    queryset = SystemSettings.objects.all()
    REQUIRED_GROUPS = {
        'READ': ('rules.configuration_view', 'rules.events_view'),
        'WRITE': ('rules.configuration_edit',),
    }
    no_tenant_check = True

    def retrieve(self, request, pk=None):
        from scirius.utils import get_middleware_module

        instance = self.get_object()
        serializer = SystemSettingsSerializer(instance)
        data = serializer.data.copy()

        data['kibana'] = USE_KIBANA
        data['evebox'] = USE_EVEBOX
        data['es_keyword'] = ELASTICSEARCH_KEYWORD

        if USE_KIBANA:
            if KIBANA_PROXY:
                data['kibana_url'] = '/kibana'
            else:
                data['kibana_url'] = KIBANA_URL

        if USE_EVEBOX:
            data['evebox_url'] = '/evebox'

        data['cyberchef'] = USE_CYBERCHEF
        if USE_CYBERCHEF:
            data['cyberchef_url'] = CYBERCHEF_URL

        get_middleware_module('common').update_settings(data)
        return Response(data)

    def get_object(self):
        return get_system_settings()

    def _update_or_partial_update(self, request):
        data = request.data.copy()
        comment = data.pop('comment', None)

        # because of rest website UI
        if isinstance(comment, list):
            comment = comment[0]

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
            action_type='system_settings',
            comment=comment_serializer.validated_data['comment'],
            request=request
        )

    def update(self, request, *args, **kwargs):
        self._update_or_partial_update(request)
        return super(SystemSettingsViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        self._update_or_partial_update(request)
        return super(SystemSettingsViewSet, self).update(request, partial=True, *args, **kwargs)


class SciriusContextAPIView(APIView):
    REQUIRED_GROUPS = {
        'READ': ('rules.configuration_view', 'rules.events_view'),
    }
    no_tenant_check = True

    def get(self, request, format=None):
        from scirius.utils import get_middleware_module
        context = get_middleware_module('common').get_homepage_context()
        return Response(context)


class FilterSetSerializer(serializers.ModelSerializer):

    class Meta:
        model = FilterSet
        fields = '__all__'

    def to_internal_value(self, data):
        try:
            data['content'] = json.dumps(data['content'])
        except ValueError:
            raise serializers.ValidationError({'content': 'Not a JSON format.'})

        if not data['share']:
            data['user'] = self.context['request'].user.pk

        return super(FilterSetSerializer, self).to_internal_value(data)

    def to_representation(self, instance):
        data = super(FilterSetSerializer, self).to_representation(instance)
        data['content'] = json.loads(data['content'])
        data['share'] = 'global' if data['user'] is None else 'private'
        data.pop('user')

        # Work-around following #4388, to keep backward compatibility
        for _filter in data['content']:
            if _filter['id'] == 'search':
                _filter['id'] = 'content'
        return data


class FilterSetViewSet(viewsets.ModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Get :\n
    Show all filter sets (even static ones that have no pk):\n
        curl -k https://x.x.x.x/rest/rules/hunt_filter_sets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        [{"id":1,"content":[{"id":"alert.tag","value":{"untagged":true,"relevant":true,"informational":true}},{"negated":false,"query":"rest","id":"hits_min","value":1,"label":"Hits min: 1"},
        {"negated":false,"query":"rest","id":"hits_max","value":10,"label":"Hits max: 10"},
        {"value":2002025,"label":"alert.signature_id: 2002025","isChecked":true,"key":"alert.signature_id","negated":false,"query":"filter","id":"alert.signature_id"}],
        "name":"aze","page":"RULES_LIST","share":"global"}]

    ==== DELETE ====\n
    Delete filter set (cannot delete static ones that have no pk):\n
        curl -k https://x.x.x.x/rest/rules/hunt_filter_sets/<pk>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """
    serializer_class = FilterSetSerializer
    ordering = ('name',)
    REQUIRED_GROUPS = {
        'READ': ('rules.events_view',),
        'WRITE': ('rules.events_view',),
    }
    no_tenant_check = True

    def get_queryset(self):
        user = self.request.user
        Q = models.Q
        if user.__class__.__name__ == 'FakeUser' and settings.DEBUG:
            return FilterSet.objects.filter(user=None)
        return FilterSet.objects.filter(Q(user=user) | Q(user=None))

    @staticmethod
    def _sort_filtersets(item):
        return item['name']

    def list(self, request):
        from scirius.utils import get_middleware_module
        filters = get_middleware_module('common').get_default_filter_sets()

        queryset = self.get_queryset()
        serializer = FilterSetSerializer(queryset, many=True)
        filters = serializer.data + filters
        filters = sorted(filters, key=self._sort_filtersets)
        return Response(filters)

    def create(self, request, *args, **kwargs):
        data = request.data.copy()

        if data.get('share', False) and not request.user.has_perm('rules.events_edit'):
            raise PermissionDenied()

        serializer = FilterSetSerializer(data=data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def update(self, request, *args, **kwargs):
        if request.data.get('share', False) and not request.user.has_perm('rules.events_edit'):
            raise PermissionDenied()
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        if request.data.get('share', False) and not request.user.has_perm('rules.events_edit'):
            raise PermissionDenied()
        return super().update(request, partial=True, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        if request.data.get('share', False) and not request.user.has_perm('rules.events_edit'):
            raise PermissionDenied()
        return super().destroy(request, *args, **kwargs)


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
        {"placeholder":"Minimum Hits Count","title":"Hits min","filterType":"integer","id":"hits_min","queryType":"rest"},
        {"placeholder":"Maximum Hits Count","title":"Hits max","filterType":"integer","id":"hits_max","queryType":"rest"},
        {"placeholder":"Filter by Message","title":"Message","filterType":"text","id":"msg","queryType":"filter"},
        {"placeholder":"Filter by Content","title":"Content","filterType":"text","id":"search","queryType":"rest"},
        {"placeholder":"Filter by Signature","title":"Signature ID","filterType":"text","id":"sid","queryType":"filter"}]

    =============================================================================================================================================================
    """

    REQUIRED_GROUPS = {
        'READ': ('rules.events_view',),
    }
    no_tenant_check = True

    def get(self, request, format=None):
        from scirius.utils import get_middleware_module
        filters = get_middleware_module('common').get_hunt_filters()
        return Response(filters)


class ESUniqueFieldViewSet(ESBaseViewSet):
    REQUIRED_GROUPS = {
        'READ': ('rules.events_view',),
    }

    def _get(self, request, format=None) -> object:
        return Response(ESGetUniqueFields(request).get(request.query_params.get("event_type", None)))


class ESFieldUniqViewSet(ESBaseViewSet):
    REQUIRED_GROUPS = {
        'READ': ('rules.events_view',),
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
        'READ': ('rules.events_view',),
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
            d_graph["nodes"].append({
                "index": str(b["key"]),
                "field": col_src,
                "kind": "source",
            })

        # pass 2 insert destination nodes
        for b in buckets:
            for b2 in b.get("col_dest", {}).get("buckets", []):
                d_graph["nodes"].append({
                    "index": str(b2["key"]),
                    "field": col_dest,
                    "kind": "destination"
                })

        # pass 3 insert edges
        for b in buckets:
            for b2 in b.get("col_dest", {}).get("buckets", []):
                d_graph["edges"].append({
                    "edge": [str(b["key"]), str(b2["key"])],
                    "doc_count": b2["doc_count"]
                })

        return d_graph

    def _get(self, request, format=None) -> dict:
        data = ESGraphAgg(request).get()
        if len(data) == 0:
            return Response("No data", status=status.HTTP_400_BAD_REQUEST)

        col_src = request.GET.get("col_src", "src_ip")
        col_dest = request.GET.get("col_dest", "dest_ip")

        graph = self._fmt_networkx(data, col_src, col_dest)

        return Response({
            "graph": graph,
        })


def get_custom_urls():
    urls = []
    url_ = re_path(r'rules/system_settings/$', SystemSettingsViewSet.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update',
    }), name='systemsettings')

    urls.append(url_)

    url_ = re_path(r'rules/hunt-filter/$', HuntFilterAPIView.as_view(), name='hunt_filter')
    urls.append(url_)

    urls.append(re_path(r'rules/es/rules/$', ESRulesViewSet.as_view(), name='es_rules'))
    urls.append(re_path(r'rules/es/rule/$', ESRuleViewSet.as_view(), name='es_rule'))
    urls.append(re_path(r'rules/es/filter_ip/$', ESFilterIPViewSet.as_view(), name='es_filter_ip'))
    urls.append(re_path(r'rules/es/field_stats/$', ESFieldStatsViewSet.as_view(), name='es_field_stats'))
    urls.append(re_path(r'rules/es/fields_stats/$', ESFieldsStatsViewSet.as_view(), name='es_fields_stats'))
    urls.append(re_path(r'rules/es/poststats_summary/$', ESPostStatsViewSet.as_view(), name='es_poststats_summary'))
    urls.append(re_path(r'rules/es/sigs_list/$', ESSigsListViewSet.as_view(), name='es_sigs_list'))
    urls.append(re_path(r'rules/es/top_rules/$', ESTopRulesViewSet.as_view(), name='es_top_rules'))
    urls.append(re_path(r'rules/es/timeline/$', ESTimelineViewSet.as_view(), name='es_timeline'))
    urls.append(re_path(r'rules/es/logstash_eve/$', ESLogstashEveViewSet.as_view(), name='es_logstash_eve'))
    urls.append(re_path(r'rules/es/health/$', ESHealthViewSet.as_view(), name='es_health'))
    urls.append(re_path(r'rules/es/stats/$', ESStatsViewSet.as_view(), name='es_stats'))
    urls.append(re_path(r'rules/es/shard_stats/$', ESShardStatsViewSet.as_view(), name='es_shard_stats'))
    urls.append(re_path(r'rules/es/check_version/$', ESCheckVersionViewSet.as_view(), name='es_check_version'))
    urls.append(re_path(r'rules/es/rules_per_category/$', ESRulesPerCategoryViewSet.as_view(), name='es_rules_per_category'))
    urls.append(re_path(r'rules/es/alerts_count/$', ESAlertsCountViewSet.as_view(), name='es_alerts_count'))
    urls.append(re_path(r'rules/es/alerts_timerange/$', ESTimeRangeAllAlertsViewSet.as_view(), name='es_alerts_timerange'))
    urls.append(re_path(r'rules/es/latest_stats/$', ESLatestStatsViewSet.as_view(), name='es_latest_stats'))
    urls.append(re_path(r'rules/es/ip_pair_alerts/$', ESIPPairAlertsViewSet.as_view(), name='es_ip_pair_alerts'))
    urls.append(re_path(r'rules/es/ip_pair_network_alerts/$', ESIPPairNetworkAlertsViewSet.as_view(), name='es_ip_pair_network_alerts'))
    urls.append(re_path(r'rules/es/alerts_tail/$', ESAlertsTailViewSet.as_view(), name='es_alerts_tail'))
    urls.append(re_path(r'rules/es/events_tail/$', ESEventsTailViewSet.as_view(), name='es_events_tail'))
    urls.append(re_path(r'rules/es/tls_tail/$', ESTLSTailViewSet.as_view(), name='es_tls_tail'))
    urls.append(re_path(r'rules/es/events_timeline/$', ESEventsTimelineViewSet.as_view(), name='es_events_timeline'))
    urls.append(re_path(r'rules/es/flow_timeline/$', ESFlowTimelineViewSet.as_view(), name='es_flow_timeline'))
    urls.append(re_path(r'rules/es/ip_flow_timeline/$', ESIPFlowTimelineViewSet.as_view(), name='es_ip_flow_timeline'))
    urls.append(re_path(r'rules/es/events_from_flow_id/$', ESEventsFromFlowIDViewSet.as_view(), name='es_events_from_flow_id'))
    urls.append(re_path(r'rules/es/suri_log_tail/$', ESSuriLogTailViewSet.as_view(), name='es_suri_log_tail'))
    urls.append(re_path(r'rules/es/delete_logs/$', ESDeleteLogsViewSet.as_view(), name='es_delete_logs'))
    urls.append(re_path(r'rules/scirius_context/$', SciriusContextAPIView.as_view(), name='scirius_context'))
    urls.append(re_path(r'rules/es/unique_fields/$', ESUniqueFieldViewSet.as_view(), name='es_unique_fields'))
    urls.append(re_path(r'rules/es/graph_agg/$', ESGraphAggViewSet.as_view(), name='es_graph_agg'))
    urls.append(re_path(r'rules/es/unique_values/$', ESFieldUniqViewSet.as_view(), name='es_unique_values'))

    return urls


router = DefaultRouter()
router.register('rules/ruleset', RulesetViewSet)
router.register('rules/category', CategoryViewSet)
router.register('rules/rule', RuleViewSet)
router.register('rules/source', SourceViewSet, basename='source')
router.register('rules/public_source', PublicSourceViewSet, basename='publicsource')
router.register('rules/transformation/ruleset', RulesetTransformationViewSet)
router.register('rules/transformation/category', CategoryTransformationViewSet)
router.register('rules/transformation/rule', RuleTransformationViewSet)
router.register('rules/history', UserActionViewSet)
router.register('rules/changelog/source', ChangelogViewSet)
router.register('rules/system_settings', SystemSettingsViewSet)
router.register('rules/processing-filter', RuleProcessingFilterViewSet)
router.register('rules/hunt_filter_sets', FilterSetViewSet, basename='hunt_filter_sets')
