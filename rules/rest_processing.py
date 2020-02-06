"""
Copyright(C) 2018 Stamus Networks
Written by Laurent Defert <lds@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import unicode_literals
import json
from IPy import IP

from django.db import models
from rest_framework import serializers, viewsets, exceptions
from rest_framework.decorators import list_route
from rest_framework.response import Response

from rules.models import RuleProcessingFilter, RuleProcessingFilterDef, Threshold, UserAction, Rule
from scirius.rest_utils import SciriusModelViewSet


class RuleProcessingFilterDefSerializer(serializers.ModelSerializer):
    IP_FIELDS = ('src_ip', 'dest_ip', 'alert.source.ip', 'alert.target.ip', 'dns.rdata', 'dns.answers.rdata', 'dns.grouped.A')

    class Meta:
        model = RuleProcessingFilterDef
        fields = ('pk', 'key', 'value', 'operator', 'full_string')
        read_only_fields = ('pk',)

    def to_representation(self, instance):
        data = super(RuleProcessingFilterDefSerializer, self).to_representation(instance)
        if instance.key == 'alert.signature_id':
            try:
                data['msg'] = Rule.objects.get(sid=instance.value).msg
            except Rule.DoesNotExist:
                pass
        return data

    def validate(self, data):
        if data['key'] in self.IP_FIELDS:
            try:
                addr = IP(data['value'])
                if data['operator'] == 'contains' and len(addr) == 1:
                    raise ValueError('not a network address')
            except ValueError:
                _type = 'IP'
                if data['operator'] == 'contains':
                    _type = 'network'
                raise serializers.ValidationError({'value': ['This field requires a valid %s address.' % _type]})
        return data


class JSONStringField(serializers.Field):
    def to_representation(self, data):
        if data is None:
            return None
        data = json.loads(data)
        return data

    def to_internal_value(self, data):
        return json.dumps(data)


class ThresholdOptionsSerializer(serializers.Serializer):
    type = serializers.ChoiceField(Threshold.THRESHOLD_TYPE_TYPES)
    count = serializers.IntegerField(default=1, min_value=0)
    seconds = serializers.IntegerField(default=60, min_value=0)
    track = serializers.ChoiceField((('by_src', 'By source'), ('by_dst', 'By destination')))


ACTION_OPTIONS_SERIALIZER = {
    'threshold': ThresholdOptionsSerializer,
}


class RuleProcessingFilterSerializer(serializers.ModelSerializer):
    filter_defs = RuleProcessingFilterDefSerializer(many=True)
    index = serializers.IntegerField(default=None, allow_null=True)
    options = JSONStringField(default=None, allow_null=True)
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True, allow_null=True)

    class Meta:
        model = RuleProcessingFilter
        fields = ('pk', 'filter_defs', 'action', 'options', 'rulesets', 'index', 'description', 'enabled', 'comment')

    def __init__(self, *args, **kwargs):
        super(RuleProcessingFilterSerializer, self).__init__(*args, **kwargs)
        self.option_serializer = None

    def to_representation(self, instance):
        if not instance.options:
            from scirius.utils import get_middleware_module
            instance = get_middleware_module('common').update_proessing_filter_action_options(instance)
        return super(RuleProcessingFilterSerializer, self).to_representation(instance)

    def to_internal_value(self, data):
        from scirius.utils import get_middleware_module

        options = data.get('options')
        action = data.get('action')

        action_options_serializer = get_middleware_module('common').update_processing_filter_action_options_serializer(ACTION_OPTIONS_SERIALIZER)
        serializer = action_options_serializer.get(action)

        if serializer:
            serializer = serializer(data=options)
            try:
                serializer.is_valid(raise_exception=True)
            except serializers.ValidationError as e:
                raise serializers.ValidationError({'options': [e.detail]})
            options = serializer.validated_data
        else:
            if options:
                raise serializers.ValidationError({'options': ['Action "%s" does not accept options.' % action]})
            options = {}

        if not isinstance(serializer, serializers.ModelSerializer):
            if self.partial:
                if 'options' in data:
                    data['options'] = options
            else:
                data['options'] = options
        else:
            self.option_serializer = serializer
            data.pop('options', None)

        return super(RuleProcessingFilterSerializer, self).to_internal_value(data)

    def validate(self, data):
        from scirius.utils import get_middleware_module
        get_middleware_module('common').validate_rule_postprocessing(data, self.partial)
        return data

    def _set_filters(self, instance, filters):
        current_filters = instance.filter_defs.all()
        filters_pk = []

        for f in filters:
            f['proc_filter'] = instance
            serializer = RuleProcessingFilterDefSerializer(data=f)
            try:
                serializer.is_valid(raise_exception=True)
            except serializers.ValidationError as e:
                raise serializers.ValidationError({'filter_defs': [e.detail]})

            # Update existing, create new ones
            if f.get('pk'):
                f_obj = current_filters.get(pk=f['pk'])
                f_obj = serializer.update(f_obj, f)
                filters_pk.append(f_obj.pk)
            else:
                f_obj = serializer.create(f)
                filters_pk.append(f_obj.pk)

        # Remove deleted filters
        for f_obj in current_filters:
            if f_obj.pk not in filters_pk:
                f_obj.delete()

    def _reorder(self, instance, previous_index, new_index):
        if new_index is previous_index:
            return

        if previous_index is not None:
            if previous_index < new_index:
                if new_index != previous_index + 1:
                    # No need to update when the object is inserted before the next object
                    RuleProcessingFilter.objects.filter(index__gt=previous_index, index__lt=new_index).update(index=models.F('index') - 1)

                instance.index -= 1
                instance.save()

            if previous_index > new_index:
                RuleProcessingFilter.objects.filter(index__gte=new_index, index__lt=previous_index).exclude(pk=instance.pk).update(index=models.F('index') + 1)
        else:
            RuleProcessingFilter.objects.filter(index__gte=new_index).exclude(pk=instance.pk).update(index=models.F('index') + 1)

    def _update_or_create(self, operation, instance, validated_data):
        filters = validated_data.pop('filter_defs', None)
        comment = validated_data.pop('comment', None)
        previous_index = None
        new_index = None
        index_max = RuleProcessingFilter.objects.aggregate(models.Max('index'))['index__max']

        if operation == 'create':
            if not filters:
                # Error on null and empt list
                raise serializers.ValidationError({'filter_defs': ['This field is required.']})

            if validated_data.get('index') is None:
                if index_max is None:
                    validated_data['index'] = 0
                else:
                    validated_data['index'] = index_max + 1
                    
            else:
                new_index = validated_data['index']
                if new_index != 0 and (index_max is None or new_index > index_max + 1):
                    raise serializers.ValidationError({'index': ['Invalid index value (too high).']})

            instance = super(RuleProcessingFilterSerializer, self).create(validated_data)
            user_action = 'create'

            if self.option_serializer and hasattr(self.option_serializer.Meta.model, 'action'):
                self.option_serializer.save(action=instance)
        else:
            if filters is not None and len(filters) == 0:
                # Error on empty list only
                raise serializers.ValidationError({'filter_defs': ['This field is required.']})

            if 'index' in validated_data:
                previous_index = instance.index
                new_index = validated_data['index']
                if new_index is None:
                    new_index = index_max + 1
                    validated_data['index'] = new_index
                elif new_index > index_max + 1:
                    raise serializers.ValidationError({'index': ['Invalid index value (too high).']})

            instance = super(RuleProcessingFilterSerializer, self).update(instance, validated_data)
            user_action = 'edit'

        self._reorder(instance, previous_index, new_index)

        if filters:
            try:
                self._set_filters(instance, filters)
            except:
                if operation == 'create':
                    instance.delete()
                raise

        UserAction.create(
                action_type='%s_rule_filter' % user_action,
                comment=comment,
                user=self.context['request'].user,
                rule_filter=instance
        )
        return instance

    update = lambda self, instance, validated_data: RuleProcessingFilterSerializer._update_or_create(self, 'update', instance, validated_data)
    create = lambda self, validated_data: RuleProcessingFilterSerializer._update_or_create(self, 'create', None, validated_data)


class RuleProcessingTestSerializer(serializers.Serializer):
    fields = serializers.ListField(child=serializers.CharField(max_length=256))
    action = serializers.ChoiceField((('suppress', 'Suppress'),
                                      ('threshold', 'Threshold'),
                                      ('tag', 'Tag'),
                                      ('tagkeep', 'Tag and Keep'),
                                      ('threat', 'Threat'),
                                      ('send_mail', 'Send email')), allow_null=True)


class RuleProcessingTestActionsSerializer(serializers.Serializer):
    fields = serializers.ListField(child=serializers.CharField(max_length=256))


class RuleProcessingFilterIntersectSerializer(serializers.Serializer):
    filter_defs = RuleProcessingFilterDefSerializer(many=True)
    index = serializers.IntegerField(default=None, allow_null=True)


class RuleProcessingFilterViewSet(SciriusModelViewSet):
    '''
    =============================================================================================================================================================
    ==== GET ====\n
    List all actions:\n
        curl -k https://x.x.x.x/rest/rules/processing-filter/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"count":2,"next":null,"previous":null,"results":[{"pk":2,"filter_defs":[{"key":"alert.signature_id","value":"2000005","operator":"equal"}],"action":"threshold","options":{"count":10,"seconds":60,"type":"both","track":"by_src"},"rulesets":[1],"index":0,"description":"","enabled":true},{"pk":1,"filter_defs":[{"key":"src_ip","value":"192.168.0.1","operator":"equal"}],"action":"suppress","options":{},"rulesets":[1],"index":1,"description":"","enabled":true}]}

    ==== POST ====\n
    Append a suppression/thsreshold/tag/tagkeep action:\n
        curl -k https://x.x.x.x/rest/rules/processing-filter/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"filter_defs": [{"key": "src_ip", "value": "192.168.0.1", "operator": "equal"}], "action": "suppress", "rulesets": [1]}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":1,"filter_defs":[{"key":"src_ip","value":"192.168.0.1","operator":"equal"}],"action":"suppress","options":{},"rulesets":[1],"index":0,"description":"","enabled":true}

    Insert a threshold action before current first action:\n
        curl -k https://x.x.x.x/rest/rules/processing-filter/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"filter_defs": [{"key": "alert.signature_id", "value": "2000005", "operator": "equal"}], "action": "threshold", "rulesets": [1], "options": {"type": "both", "count": 10, "seconds": 60, "track": "by_src"}, "index": 0}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":2,"filter_defs":[{"key":"alert.signature_id","value":"2000005","operator":"equal"}],"action":"threshold","options":{"count":10,"seconds":60,"type":"both","track":"by_src"},"rulesets":[1],"index":0,"description":"","enabled":true}

    List the action capabilities supported by the backend:\n
        curl -k https://x.x.x.x/rest/rules/processing-filter/test/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"fields": ["alert.signature_id", "src_ip"], "action": "suppress"}'

    Return:\n
        HTTP/1.1 200 OK
        {"fields":["alert.signature_id","src_ip"],"operators":["equal","different","contains"]}

    List existing actions with a common key, before <index>:\n
        curl -k https://x.x.x.x/rest/rules/processing-filter/intersect/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"filter_defs": [{"key": "src_ip", "value": "192.168.3.2", "operator": "equal"}], "index": 1}'

    Return:\n
        HTTP/1.1 200 OK
        {"count":1,"next":null,"previous":null,"results":[{"pk":1,"filter_defs":[{"key":"src_ip","value":"192.168.3.2","operator":"equal"}],"action":"suppress","options":{},"rulesets":[1],"index":0,"description":"","enabled":true}]}

    ==== PATCH ====\n
    Move the action with <pk> before currently at <index>:\n
        curl -k https://x.x.x.x/rest/rules/processing-filter/<pk>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X PATCH -d '{"index": <index>}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":2,"filter_defs":[{"key":"alert.signature_id","value":"2000005","operator":"equal"}],"action":"threshold","options":{},"rulesets":[1],"index":1,"description":"","enabled":true}l

    ==== DELETE ====\n
    Remove an action:\n
        curl -k https://x.x.x.x/rest/rules/processing-filter/<pk>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    '''

    queryset = RuleProcessingFilter.objects.all()
    serializer_class = RuleProcessingFilterSerializer
    ordering = ('index',)
    ordering_fields = ('pk', 'index', 'action', 'enabled')
    filter_fields = ('action', 'enabled', 'filter_defs__key', 'filter_defs__value')
    search_fields = ('description', 'filter_defs__key', 'filter_defs__value')

    def destroy(self, request, *args, **kwargs):
        from rules.rest_api import CommentSerializer
        comment_serializer = CommentSerializer(data=request.data)
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
                action_type='delete_rule_filter',
                comment=comment_serializer.validated_data.get('comment'),
                user=request.user,
                rule_filter=self.get_object()
        )

        index = self.get_object().index
        response = super(RuleProcessingFilterViewSet, self).destroy(request, *args, **kwargs)

        # Update index values
        RuleProcessingFilter.objects.filter(index__gt=index).update(index=models.F('index') - 1)
        return response

    @list_route(methods=['post'])
    def test(self, request):
        from scirius.utils import get_middleware_module
        fields_serializer = RuleProcessingTestSerializer(data=request.data)
        fields_serializer.is_valid(raise_exception=True)
        capabilities = get_middleware_module('common').get_processing_filter_capabilities(fields_serializer.validated_data['fields'], fields_serializer.validated_data['action'])
        return Response(capabilities)

    @list_route(methods=['post'])
    def test_actions(self, request):
        from scirius.utils import get_middleware_module
        fields_serializer = RuleProcessingTestActionsSerializer(data=request.data)
        fields_serializer.is_valid(raise_exception=True)
        capabilities = get_middleware_module('common').get_processing_actions_capabilities(fields_serializer.validated_data.get('fields'))
        return Response({'actions': capabilities})

    @list_route(methods=['post'])
    def intersect(self, request):
        from scirius.utils import get_middleware_module
        fields_serializer = RuleProcessingFilterIntersectSerializer(data=request.data)
        fields_serializer.is_valid(raise_exception=True)
        index = fields_serializer.validated_data.get('index', None)
        if index is None:
            rf = RuleProcessingFilter.objects.all()
        else:
            rf = RuleProcessingFilter.objects.filter(index__lt=index)

        # Match filters keys
        keys = [f['key'] for f in fields_serializer.validated_data['filter_defs']]
        matching_rf = rf.filter(filter_defs__key__in=keys)

        lst = matching_rf.distinct().order_by('index')

        # Paginate response
        page = self.paginate_queryset(lst)
        serializer = self.get_serializer(page, many=True)
        return self.get_paginated_response(serializer.data)
