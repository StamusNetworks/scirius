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

import json

from django.db import models
from rest_framework import serializers, viewsets, exceptions

from rules.models import RuleProcessingFilter, RuleProcessingFilterDef, Threshold


class RuleProcessingFilterDefSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleProcessingFilterDef
        exclude = ('id', 'proc_filter')


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


class TagOptionsSerializer(serializers.Serializer):
    tag = serializers.CharField(max_length=256)


ACTION_OPTIONS_SERIALIZER = {
    'threshold': ThresholdOptionsSerializer,
    'tag': TagOptionsSerializer,
    'tagkeep': TagOptionsSerializer,
}


class RuleProcessingFilterSerializer(serializers.ModelSerializer):
    filter_defs = RuleProcessingFilterDefSerializer(many=True)
    index = serializers.IntegerField(default=None, allow_null=True)
    options = JSONStringField(default=None, allow_null=True)

    class Meta:
        model = RuleProcessingFilter
        fields = ('pk', 'filter_defs', 'action', 'options', 'index', 'description', 'enabled')

    def to_internal_value(self, data):
        options = data.get('options')
        action = data.get('action')

        serializer = ACTION_OPTIONS_SERIALIZER.get(action)

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

        data['options'] = options
        return super(RuleProcessingFilterSerializer, self).to_internal_value(data)

    def validate(self, data):
        from scirius.utils import get_middleware_module
        try:
            get_middleware_module('common').validate_rule_postprocessing(data)
            return data
        except AttributeError:
            pass

        action = data.get('action')
        if action not in ('suppress', 'threshold'):
            raise serializers.ValidationError('Action "%s" is not supported.' % action)

        has_sid = False
        has_ip = False
        has_bad_operator = False

        for f in data.get('filter_defs', []):
            if f.get('key') == 'alert.signature_id':
                has_sid = True

            if f.get('key') in ('src_ip', 'dest_ip'):
                if action == 'suppress':
                    if has_ip:
                        raise serializers.ValidationError({'filter_defs': ['Only one field with key "src_ip" or "dest_ip" is accepted.']})
                    has_ip = True
                else:
                    raise serializers.ValidationError({'filter_defs': ['Field "%s" is not supported for threshold.' % f['key']]})

            if f.get('operator') != 'equal':
                has_bad_operator = True

        errors = []
        if not has_sid:
            errors.append('A filter with a key "alert.signature_id" is required.')
        if not has_ip:
            errors.append('A filter with a key "src_ip" or "dest_ip" is required.')
        if has_bad_operator:
            errors.append('Only operator "equal" is supported.')

        if errors:
            raise serializers.ValidationError({'filter_defs': errors})

        return data

    def _set_filters(self, instance, filters):
        current_filters = instance.filter_defs.all()

        for f in filters:
            f['proc_filter'] = instance
            serializer = RuleProcessingFilterDefSerializer(data=f)
            try:
                serializer.is_valid(raise_exception=True)
            except serializers.ValidationError as e:
                raise serializers.ValidationError({'filter_defs': [e.detail]})

            # Update existing, create new ones
            try:
                f_obj = current_filters.get(key=f['key'])
            except models.ObjectDoesNotExist:
                f_obj = serializer.create(f)
                continue

            f_obj = serializer.update(f_obj, f)

        # Remove deleted filters
        for f_obj in current_filters:
            if f_obj.key not in [f['key'] for f in filters]:
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

        self._reorder(instance, previous_index, new_index)

        if filters:
            try:
                self._set_filters(instance, filters)
            except:
                if operation == 'create':
                    instance.delete()
                raise

        return instance

    update = lambda self, instance, validated_data: RuleProcessingFilterSerializer._update_or_create(self, 'update', instance, validated_data)
    create = lambda self, validated_data: RuleProcessingFilterSerializer._update_or_create(self, 'create', None, validated_data)


class RuleProcessingFilterViewSet(viewsets.ModelViewSet):
    queryset = RuleProcessingFilter.objects.all()
    serializer_class = RuleProcessingFilterSerializer
    ordering = ('index',)
    ordering_fields = ('pk', 'index', 'action', 'enabled')
    filter_fields = ('action', 'enabled', 'filter_defs__key', 'filter_defs__value')
    search_fields = ('description', 'filter_defs__key', 'filter_defs__value')

    def destroy(self, request, *args, **kwargs):
        index = self.get_object().index
        response = super(RuleProcessingFilterViewSet, self).destroy(request, *args, **kwargs)

        # Update index values
        RuleProcessingFilter.objects.filter(index__gt=index).update(index=models.F('index') - 1)
        return response
