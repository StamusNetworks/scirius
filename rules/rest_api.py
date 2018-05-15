from suripyg import SuriHTMLFormat

from django.conf import settings
from django.utils import timezone
from django.utils.html import escape
from django.db.models import Q
from collections import OrderedDict

from django.core.exceptions import SuspiciousOperation, ValidationError

from rest_framework.validators import UniqueValidator
from rest_framework import serializers, viewsets, exceptions, mixins
from rest_framework.decorators import detail_route, list_route
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import serializers, viewsets
from rest_framework.decorators import detail_route, list_route
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.response import Response
from rest_framework.exceptions import APIException, ParseError
from rest_framework.routers import DefaultRouter, url
from rest_framework import status
from rest_framework.parsers import MultiPartParser, JSONParser
from rest_framework.mixins import UpdateModelMixin, RetrieveModelMixin
from rest_framework.permissions import IsAdminUser

from django_filters import rest_framework as filters
from django_filters import fields as filters_fields

from rules.models import Rule, Category, Ruleset, RuleTransformation, CategoryTransformation, RulesetTransformation, \
        Source, SourceAtVersion, SourceUpdate, UserAction, UserActionObject, Transformation, SystemSettings, get_system_settings
from rules.views import get_public_sources, fetch_public_sources
from rules.rest_processing import RuleProcessingFilterViewSet

from scirius.rest_api import SciriusReadOnlyModelViewSet, SciriusModelViewSet
from rules.es_graphs import es_get_sigs_list_hits, es_get_top_rules

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

    class Meta:
        model = Ruleset
        fields = ('pk', 'name', 'descr', 'created_date', 'updated_date', 'need_test', 'validity',
                  'errors', 'rules_count', 'sources', 'categories', 'comment')
        read_only_fields = ('pk', 'created_date', 'updated_date', 'need_test', 'validity', 'errors',
                            'rules_count')
        extra_kwargs = {
        }

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
    filter_fields = ('name', 'descr')

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

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
                action_type='create_ruleset',
                comment=comment_serializer.validated_data['comment'],
                user=request.user,
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
                user=request.user,
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

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
                action_type='edit_ruleset',
                comment=comment_serializer.validated_data['comment'],
                user=request.user,
                ruleset=instance
        )

    def update(self, request, *args, **kwargs):
        self._update_or_partial_update(request, False)
        return super(RulesetViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        self._update_or_partial_update(request, True)
        return super(RulesetViewSet, self).update(request, partial=True, *args, **kwargs)

    @detail_route(methods=['post'])
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
                user=request.user,
                ruleset=ruleset
            )

        return Response({'copy': 'ok'})


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
    filter_fields = ('name', 'source', 'created_date')

    @detail_route(methods=['post'])
    def enable(self, request, pk):
        category = self.get_object()
        serializer = CategoryChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        category.enable(serializer.validated_data['ruleset'], request.user,
                serializer.validated_data.get('comment', None))
        return Response({'enable': 'ok'})

    @detail_route(methods=['post'])
    def disable(self, request, pk):
        category = self.get_object()
        serializer = CategoryChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        category.disable(serializer.validated_data['ruleset'], request.user,
                serializer.validated_data.get('comment', None))
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


class RuleSerializer(serializers.ModelSerializer):
    category = CategorySerializer(read_only=True)
    hits = serializers.IntegerField(read_only=True)
    timeline_data = HitTimelineEntry(many=True, read_only=True)

    class Meta:
        model = Rule
        fields = ('pk', 'sid', 'category', 'msg', 'state', 'state_in_source', 'rev', 'content',
                  'imported_date', 'updated_date', 'created', 'updated', 'hits', 'timeline_data')

    def to_representation(self, instance):
        data = super(RuleSerializer, self).to_representation(instance)
        request = self.context['request']
        highlight_str = request.query_params.get('highlight', u'false')
        is_highlight = lambda value: bool(value) and value.lower() not in (u'false', u'0')
        highlight = is_highlight(highlight_str)

        if highlight is True:
            data['content'] = SuriHTMLFormat(data['content'])

        return data


class ListFilter(filters.CharFilter):

    def sanitize(self, value_list):
        """
        remove empty items in case of ?number=1,,2
        """
        return [v for v in value_list if v != u'']

    def customize(self, value):
        return value

    def filter(self, qs, value):
        multiple_vals = value.split(u",")
        multiple_vals = self.sanitize(multiple_vals)
        multiple_vals = map(self.customize, multiple_vals)
        for val in multiple_vals:
            fval = filters_fields.Lookup(val, 'icontains')
            qs =  super(ListFilter, self).filter(qs, fval)
        return qs


class RuleFilter(filters.FilterSet):
    min_created = filters.DateFilter(name="created", lookup_expr='gte')
    max_created = filters.DateFilter(name="created", lookup_expr='lte')
    min_updated = filters.DateFilter(name="updated", lookup_expr='gte')
    max_updated = filters.DateFilter(name="updated", lookup_expr='lte')
    msg = ListFilter(name="msg", lookup_expr='icontains')
    content = ListFilter(name="content", lookup_expr='icontains')

    class Meta:
        model = Rule
        fields = ['sid', 'category', 'msg', 'content', 'created', 'updated']


def es_hits_params(request):
    es_params = {}

    # string args
    for arg in ('hostname', 'qfilter'):
        if arg in request.query_params:
            es_params[arg] = request.query_params[arg]

    # numeric args
    for arg in ('from_date', 'interval'):
        if arg in request.query_params:
            es_params[arg] = int(request.query_params[arg])

    if 'hostname' not in es_params:
        es_params['hostname'] = '*'
    return es_params


class RuleHitsOrderingFilter(OrderingFilter):
    def _get_hits_order(self, request, order):
        es_top_kwargs = {
            'count': Rule.objects.count(),
            'order': order
        }
        es_top_kwargs.update(es_hits_params(request))
        result = es_get_top_rules(request, **es_top_kwargs)
        return [r['key'] for r in result]

    def filter_queryset(self, request, queryset, view):
        ordering = self.get_ordering(request, queryset, view)

        if 'hits' in ordering or '-hits' in ordering:
            if ordering[0] not in ('hits', '-hits'):
                raise ParseError('hits ordering can only be the first ordering term')

            ordering = ordering[1:]

            if ordering:
                queryset = queryset.order_by(*ordering)

            # Index rules by sid
            rules = OrderedDict([(r.sid, r) for r in queryset])

            # Sorting
            order = 'asc' if 'hits' in ordering else 'desc'
            hits_order = self._get_hits_order(request, order)

            queryset = []
            for sid in hits_order:
                try:
                    queryset.append(rules.pop(sid))
                except KeyError:
                    pass

            # Append rules with no hit
            queryset += rules.values()
        elif ordering:
            return queryset.order_by(*ordering)

        return queryset


class RuleViewSet(SciriusReadOnlyModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show a rule and its none transformed content:\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":2404150,"sid":2404150,"category":27,"msg":"ET CNC Zeus Tracker Reported CnC Server group 1","state":true,"state_in_source":true,"rev":4983,"content":"alert ip $HOME_NET any -> [101.200.81.187,103.19.89.118,103.230.84.239,103.4.52.150,103.7.59.135] any (msg:\\"ET CNC Zeus Tracker Reported CnC Server group 1\\"; reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,zeustracker.abuse.ch; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404150; rev:4983;)","imported_date":"2018-05-04T10:15:52.886070+02:00","updated_date":"2018-05-04T10:15:52.886070+02:00"}

    Show a rule and its none transformed content in html:\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/\highlight=true -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":2404000,"sid":2404000,"category":28,"msg":"ET CNC Shadowserver Reported CnC Server IP group 1","state":true,"state_in_source":true,"rev":5032,
        "content":"<div class=\"highlight\"><pre><span></span><span class=\"kt\">alert</span><span class=\"w\"> </span><span class=\"kc\">ip</span><span class=\"w\"> 
        </span><span class=\"nv\">$HOME_NET</span><span class=\"w\"> </span><span class=\"nv\">any</span><span class=\"w\"> </span><span class=\"o\">-&gt;</span>
        <span class=\"w\"> </span><span class=\"err\">[</span><span class=\"nv\">109.196.130.50</span><span class=\"err\">,</span><span class=\"nv\">151.13.184.200</span>
        <span class=\"err\">]</span><span class=\"w\"> </span><span class=\"nv\">any</span><span class=\"w\"> </span><span class=\"err\">(</span><span class=\"k\">msg:</span>
        <span class=\"s\">&quot;ET CNC Shadowserver Reported CnC Server IP group 1&quot;</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">reference:</span>
        <span class=\"nv\">url</span><span class=\"p\">,</span><span class=\"na\">doc.emergingthreats.net/bin/view/Main/BotCC</span><span class=\"p\">;</span><span class=\"w\"> </span>
        <span class=\"k\">reference:</span><span class=\"nv\">url</span><span class=\"p\">,</span><span class=\"na\">www.shadowserver.org</span><span class=\"p\">;</span>
        <span class=\"w\"> </span><span class=\"k\">threshold:</span><span class=\"w\"> </span><span class=\"na\">type</span><span class=\"w\"> </span>
        <span class=\"na\">limit</span><span class=\"err\">,</span><span class=\"w\"> </span><span class=\"na\">track</span><span class=\"w\"> </span><span class=\"na\">by_src</span>
        <span class=\"err\">,</span><span class=\"w\"> </span><span class=\"na\">seconds</span><span class=\"w\"> </span><span class=\"m\">3600</span><span class=\"err\">,</span>
        <span class=\"w\"> </span><span class=\"na\">count</span><span class=\"w\"> </span><span class=\"m\">1</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">flow</span>
        <span class=\"err\">bits</span><span class=\"k\">:</span><span class=\"na\">set</span><span class=\"err\">,ET.Evil</span><span class=\"p\">;</span><span class=\"w\"> </span>
        <span class=\"k\">flow</span><span class=\"err\">bits</span><span class=\"k\">:</span><span class=\"na\">set</span><span class=\"err\">,ET.BotccIP</span><span class=\"p\">;</span>
        <span class=\"w\"> </span><span class=\"k\">classtype:</span><span class=\"err\">trojan-activity</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">sid:</span>
        <span class=\"m\">2404000</span><span class=\"p\">;</span><span class=\"w\"> </span><span class=\"k\">rev:</span><span class=\"m\">5032</span><span class=\"p\">;</span>
        <span class=\"err\">)</span><span class=\"w\"></span>\\n</pre></div>\\n","imported_date":"2018-06-21T15:39:05.121431+02:00","updated_date":"2018-06-21T15:39:05.121431+02:00"}

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
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/content/\?highlight=true -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

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

    Filter action/reject on all transformed rules:\n
        curl -k https://x.x.x.x/rest/rules/rule/transformation/\?transfo_type\=action\&transfo_value\=reject -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    ==== POST ====\n
    Disable a rule in a ruleset. Disabling a rule is equivalent to transform this rule to SUPPRESSED/SUPPRESSED:\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/disable/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>}'

    Return:\n
        HTTP/1.1 200 OK
        {"disable":"ok"}

    Enable a rule in a ruleset. Enabling a rule is equivalent to remove SUPPRESSED/SUPPRESSED transformation on this rule. But it can't be done from transformation API :\n
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
    filter_class = RuleFilter
    filter_backends = (DjangoFilterBackend, SearchFilter, RuleHitsOrderingFilter)
    search_fields = ('sid', 'msg', 'content')

    @list_route(methods=['get'])
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
            params_str = ', '.join(copy_params.keys())
            raise serializers.ValidationError({'filters': ['Wrong filters: "%s"' % params_str]})

        # Check key/value filters
        # Key
        if key_str:
            if key_str not in Transformation.AVAILABLE_MODEL_TRANSFO.keys():
                raise serializers.ValidationError({'filters': ['Wrong filter type "%s".' % key_str]})

            # Value
            if value_str and value_str not in Transformation.AVAILABLE_MODEL_TRANSFO[key_str]:
                raise serializers.ValidationError({'filters': ['Wrong filter value "%s" for key "%s".' % (value_str, key_str)]})

        res = {}
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

        Rule.disable_cache()
        return Response(res)

    @detail_route(methods=['get'])
    def content(self, request, pk):
        rule = self.get_object()
        rulesets = Ruleset.objects.filter(categories__rule=rule)
        res = {}

        highlight_str = request.query_params.get('highlight', u'false')
        is_highlight = lambda value: bool(value) and value.lower() not in (u'false', u'0')
        highlight = is_highlight(highlight_str)

        for ruleset in rulesets:
            content = rule.generate_content(ruleset)
            res[ruleset.pk] = content if not highlight else SuriHTMLFormat(content)

        return Response(res)

    @detail_route(methods=['post'])
    def comment(self, request, pk):
        rule = self.get_object()
        comment = request.data.get('comment', None)

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
                action_type='comment_rule',
                comment=comment,
                user=request.user,
                rule=rule
            )
        return Response({'comment': 'ok'})

    @detail_route(methods=['post'])
    def toggle_availability(self, request, pk):
        rule = self.get_object()
        comment = request.data.get('comment', None)

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        rule.toggle_availability()

        UserAction.create(
                action_type='toggle_availability',
                comment=comment,
                user=request.user,
                rule=rule
            )

        return Response({'toggle_availability': 'ok'})

    @detail_route(methods=['post'])
    def enable(self, request, pk):
        rule = self.get_object()
        serializer = RuleChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rule.enable(serializer.validated_data['ruleset'], request.user,
                serializer.validated_data.get('comment', None))
        return Response({'enable': 'ok'})

    @detail_route(methods=['post'])
    def disable(self, request, pk):
        rule = self.get_object()
        serializer = RuleChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rule.disable(serializer.validated_data['ruleset'], request.user,
                serializer.validated_data.get('comment', None))
        return Response({'disable': 'ok'})

    def get_serializer_class(self):
        if self.action in ('enable', 'disable'):
            return RuleChangeSerializer
        return RuleSerializer

    @detail_route(methods=['get'])
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

        return {
            'hits': r['doc_count'],
            'timeline_data': timeline
        }

    def _add_hits(self, request, data):
        sids = [str(rule['sid']) for rule in data]

        ## reformat ES's output
        es_params = es_hits_params(request)
        es_params['host'] = es_params.pop('hostname')
        result = es_get_sigs_list_hits(request, sids, **es_params)

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
                    'timeline_data': []
                })
        return data

    def list(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True)
        data = self._add_hits(request, serializer.data)
        return self.get_paginated_response(serializer.data)

    def _add_rule_hits(self, request, data):
        es_params = es_hits_params(request)
        es_params['host'] = es_params.pop('hostname')
        sid = str(data['sid'])
        result = es_get_sigs_list_hits(request, [sid], **es_params)
        hit = self._scirius_hit(result[0])
        data.update(hit)
        return data

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        data = self._add_rule_hits(request, serializer.data)
        return Response(data)


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
        for key, value in dict(fields).iteritems():
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
        for key, value in dict(fields).iteritems():
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
        for key, value in dict(fields).iteritems():
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

    Create a ruleset TARGET transformation (yes / auto / no):\n
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
    filter_fields = ('ruleset_transformation',)
    ordering_fields = ('ruleset_transformation',)
    _fields = {'ruleset': 'ruleset_transformation', 'trans_type': 'key', 'trans_value': 'value'}
    _action_type = 'transform_ruleset'

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
    filter_fields = ('category_transformation', 'ruleset')
    ordering_fields = ('pk', 'ruleset', 'category_transformation')
    _fields = {'ruleset': 'ruleset', 'trans_type': 'key', 'trans_value': 'value', 'category': 'category_transformation'}
    _action_type = 'transform_category'

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
    filter_fields = ('rule_transformation', 'ruleset')
    ordering_fields = ('pk', 'ruleset', 'rule_transformation')
    _fields = {'ruleset': 'ruleset', 'trans_type': 'key', 'trans_value': 'value', 'rule': 'rule_transformation'}
    _action_type = 'transform_rule'

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
                  'cats_count', 'rules_count',)
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
                user=request.user,
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
                user=request.user,
                source=source,
                comment=comment_serializer.validated_data['comment']
        )
        return super(BaseSourceViewSet, self).destroy(request, *args, **kwargs)

    def upload(self, request, pk):
        data = request.data.copy()
        comment = data.pop('comment', None)

        # because of rest website UI
        if isinstance(comment, list):
            comment = comment[0]

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)
        source = self.get_object()

        if source.method != 'local':
            msg = 'No upload is allowed. method is currently "%s"' % source.method
            raise serializers.ValidationError({'upload': [msg]})

        if not request.FILES.has_key('file'):
            raise serializers.ValidationError({'file': ['This field is required.']})

        try:
            source.handle_uploaded_file(request.FILES['file'])
        except Exception as error:
            raise serializers.ValidationError({'upload': [str(error)]})

        UserAction.create(
                action_type='upload_source',
                comment=comment_serializer.validated_data['comment'],
                user=request.user,
                source=source
        )

        return Response({'upload': 'ok'}, status=200)

    @detail_route(methods=['post'])
    def update_source(self, request, pk):
        # Do not need to copy 'request.data' and pop 'comment'
        # because we are not using serializer there
        comment = request.data.get('comment', None)
        is_async_str = request.query_params.get('async', u'false')
        is_async = lambda value: bool(value) and value.lower() not in (u'false', u'0')
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
                user=request.user,
                source=source
        )
        return Response({'update': msg})

    @list_route(methods=['get'])
    def list_sources(self, request):
        try:
            public_sources = get_public_sources(False)
        except Exception as e:
            raise serializers.ValidationError({'list': [str(e)]})
        return Response(public_sources['sources'])

    @list_route(methods=['get'])
    def fetch_list_sources(self, request):
        try:
            fetch_public_sources()
        except Exception as e:
            raise serializers.ValidationError({'fetch': [str(e)]})
        return Response({'fetch': 'ok'})

    @detail_route(methods=['post'])
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

        uri = uri % {'__version__': '4.0'}

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
    List all used sources:\n
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
        curl -k https://x.x.x.x/rest/rules/public_source/<pk-public-source>/update_source/\\?async=true -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

        curl -k https://x.x.x.x/rest/rules/public_source/<pk-public-source>/update_source/\\?async=false -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

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
    filter_fields = ('name', 'method')
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
        curl -k https://x.x.x.x/rest/rules/source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":1,"name":"Source1","created_date":"2018-05-04T10:15:46.216023+02:00","updated_date":"2018-05-04T15:22:15.267123+02:00","method":"http","datatype":"sigs","uri":"https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz","cert_verif":true,"cats_count":47,"rules_count":25490,"authkey":"123456789"}

    ==== POST ====\n
    Create custom source:\n
        curl -k https://x.x.x.x/rest/rules/source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"name": "sonic custom source", "method": "local", "datatype": "sigs"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":5,"name":"sonic Custom source","created_date":"2018-05-07T12:01:00.658118+02:00","updated_date":"2018-05-07T12:01:00.658126+02:00","method":"local","datatype":"sigs","uri":null,"cert_verif":true,"cats_count":0,"rules_count":0,"authkey":"123456789"}

    Update custom (only for {method: http}):\n
        curl -k https://x.x.x.x/rest/rules/source/<pk-source>/update_source/\\?async=true -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

        curl -k https://x.x.x.x/rest/rules/source/<pk-source>/update_source/\\?async=false -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

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
    ordering_fields = ('name', 'created_date', 'updated_date', 'cats_count', 'rules_count',)
    filter_fields = ('name', 'method')
    search_fields = ('name', 'method')

    @detail_route(methods=['post'])
    def upload(self, request, pk):
        return super(SourceViewSet, self).upload(request, pk)


class UserActionSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserAction
        fields = ('pk', 'action_type', 'date', 'comment', 'user', 'username', 'ua_objects')

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


class UserActionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show an user action :\n
        curl -k https://x.x.x.x/rest/rules/history/<pk-useraction>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"id":612,"action_type":"disable_category","date":"2018-05-14T16:13:24.711372+02:00","comment":null,"username":"scirius","description":"scirius has disabled category emerging-scada in ruleset SonicRulesetOther","user":1,"title":"Disable Category","description_raw":"{user} has disabled category {category} in ruleset {ruleset}","ua_objects":{"category":{"pk":147,"type":"Category","value":"emerging-scada"},"ruleset":{"pk":65,"type":"Ruleset","value":"SonicRulesetOther"}}}

    Ordering by username ASC:\n
        curl -k https://x.x.x.x/rest/rules/history/?ordering=username -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Ordering by username DESC:\n
        curl -k https://x.x.x.x/rest/rules/history/?ordering=-username -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Filtering by username and action_type:\n
        curl -k https://x.x.x.x/rest/rules/history/?date=&username=scirius&user_action_objects__action_key=&action_type=edit_ruleset -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Ordering & Filtering:\n
        curl -k https://x.x.x.x/rest/rules/history/?action_type=edit_ruleset&date=&ordering=username&user_action_objects__action_key=&username=scirius -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    =============================================================================================================================================================
    """

    queryset = UserAction.objects.all()
    serializer_class = UserActionSerializer
    filter_fields = ('date', 'username', 'user_action_objects__action_key', 'action_type')
    ordering = ('-pk',)
    ordering_fields = ('pk', 'date', 'username', 'action_type')


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
        curl -k https://x.x.x.x/rest/rules/changelog/source/\?source\=2 -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Show changelogs filter by version:\n
        curl -k https://x.x.x.x/rest/rules/changelog/source/\?version\=9b73cdc0e25b36ce3a80fdcced631f3769a4f6f6 -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    =============================================================================================================================================================
    """
    serializer_class = ChangelogSerializer
    queryset = SourceUpdate.objects.all()
    filter_fields = ('source', 'version')
    ordering = ('-pk',)
    ordering_fields = ('pk', 'source', 'version',)


class SystemSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemSettings
        fields = '__all__'


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
    permission_classes = (IsAdminUser,)
    serializer_class = SystemSettingsSerializer
    queryset = SystemSettings.objects.all()

    def get_object(self):
        obj = get_system_settings()
        self.check_object_permissions(self.request, obj)
        return obj

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
                user=request.user
        )

    def update(self, request, *args, **kwargs):
        self._update_or_partial_update(request)
        return super(SystemSettingsViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        self._update_or_partial_update(request)
        return super(SystemSettingsViewSet, self).update(request, partial=True, *args, **kwargs)


def get_custom_urls():
    urls = []
    url_ = url(r'rules/system_settings/$', SystemSettingsViewSet.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update',
        }), name='systemsettings')

    urls.append(url_)
    return urls


router = DefaultRouter()
router.register('rules/ruleset', RulesetViewSet)
router.register('rules/category', CategoryViewSet)
router.register('rules/rule', RuleViewSet)
router.register('rules/source', SourceViewSet, base_name='source')
router.register('rules/public_source', PublicSourceViewSet, base_name='publicsource')
router.register('rules/transformation/ruleset', RulesetTransformationViewSet)
router.register('rules/transformation/category', CategoryTransformationViewSet)
router.register('rules/transformation/rule', RuleTransformationViewSet)
router.register('rules/history', UserActionViewSet)
router.register('rules/changelog/source', ChangelogViewSet)
router.register('rules/system_settings', SystemSettingsViewSet)
router.register('rules/processing-filter', RuleProcessingFilterViewSet)
