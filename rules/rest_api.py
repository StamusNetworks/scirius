from django.conf import settings
from django.utils import timezone
from django.db.models import Q
from django.core.exceptions import SuspiciousOperation, ValidationError
from rest_framework import serializers, viewsets, exceptions
from rest_framework.decorators import detail_route, list_route
from rest_framework.response import Response
from rest_framework.exceptions import APIException
from rest_framework.routers import DefaultRouter
from rest_framework import status
from rest_framework.parsers import MultiPartParser, JSONParser

from rules.models import Rule, Category, Ruleset, RuleTransformation, CategoryTransformation, RulesetTransformation, \
        Source, SourceAtVersion, UserAction, Transformation
from rules.views import get_public_sources, fetch_public_sources


Probe = __import__(settings.RULESET_MIDDLEWARE)


class ServiceUnavailableException(APIException):
    status_code = 500
    default_detail = 'Internal Server Error, try again later.'
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


class RulesetSerializer(serializers.ModelSerializer):
    sources = serializers.PrimaryKeyRelatedField(queryset=Source.objects.all(), many=True)

    class Meta:
        model = Ruleset
        fields = ('pk', 'name', 'descr', 'created_date', 'updated_date', 'need_test', 'validity',
                  'errors', 'rules_count', 'sources', 'categories')
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
        sources = data.get('sources', None)
        if sources is None:
            return data

        sources_at_version = SourceAtVersion.objects.filter(source__in=sources)
        data['sources'] = [source_at_version.pk for source_at_version in sources_at_version]
        return data


class RulesetViewSet(viewsets.ModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Ruleset detail:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    ==== POST ====\n
    Create a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"name": "SonicRuleset", "sources": [pk-source1, ..., pk-sourceN], "categories": [pk-category1, ..., pk-categoryN]}'

    ==== PATCH ====\n
    Patch a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"name": "PatchedSonicRuleset", "categories": [pk-category1, ..., pk-categoryN]}'

    ==== PUT ====\n
    Replace a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"name": "ReplacedSonicRuleset", "comment": "sonic comment", "sources": [pk-source1, ..., pk-sourceN, "categories": [pk-category1, ..., pk-categoryN]}'

    ==== DELETE ====\n
    Delete a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X DELETE

    =============================================================================================================================================================
    """
    queryset = Ruleset.objects.all()
    serializer_class = RulesetSerializer
    ordering = ('name',)
    ordering_fields = ('name', 'created_date', 'updated_date', 'rules_count')
    filter_fields = ('name', 'descr')

    def create(self, request, *args, **kwargs):
        comment = request.data.pop('comment', None)
        serializer = RulesetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)
        ruleset = Ruleset.objects.filter(pk=serializer.data['pk'])[0]

        UserAction.create(
                action_type='create_ruleset',
                comment=comment_serializer.validated_data['comment'],
                user=request.user,
                ruleset=ruleset
        )

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        ruleset = self.get_object()
        comment = request.data.pop('comment', None)
        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
                action_type='delete_ruleset',
                user=request.user,
                ruleset=ruleset,
                comment=comment_serializer.validated_data['comment']
        )
        return super(RulesetViewSet, self).destroy(request, *args, **kwargs)

    def _update_or_partial_update(self, request, partial, *args, **kwargs):
        comment = request.data.pop('comment', None)

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

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
        self._update_or_partial_update(request, partial=False, *args, **kwargs)
        return super(RulesetViewSet, self).update(request, partial=False, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        self._update_or_partial_update(request, partial=True, *args, **kwargs)
        return super(RulesetViewSet, self).update(request, partial=True, *args, **kwargs)


class CategoryChangeSerializer(serializers.Serializer):
    ruleset = serializers.PrimaryKeyRelatedField(queryset=Ruleset.objects.all(), write_only=True)
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True)


class CategorySerializer(serializers.ModelSerializer):

    class Meta:
        model = Category
        fields = ('pk', 'name', 'filename', 'descr', 'created_date', 'source')


class CategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show a category:\n
        curl -k https://x.x.x.x/rest/rules/category/<pk-category>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'

    ==== POST ====\n
    Disable a category in a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/category/<pk-category>/disable/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>}'

    Enable a category in a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/category/<pk-category>/enable/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>}'

    =============================================================================================================================================================
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    ordering = ('name',)
    ordering_fields = ('pk', 'name', 'filename', 'created_date', 'source')
    filter_fields = ('name', 'filename', 'source', 'created_date')

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


class RuleChangeSerializer(serializers.Serializer):
    ruleset = serializers.PrimaryKeyRelatedField(queryset=Ruleset.objects.all(), write_only=True)
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True)


class RuleSerializer(serializers.ModelSerializer):

    class Meta:
        model = Rule
        fields = ('pk', 'sid', 'category', 'msg', 'state', 'state_in_source', 'rev', 'content', \
                'imported_date', 'updated_date')


class RuleViewSet(viewsets.ReadOnlyModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show a rule and its content:\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'

    ==== POST ====\n
    Disable a rule in a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/disable/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>}'

    Enable a rule in a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/rule/<sid-rule>/enable/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>}'

    =============================================================================================================================================================
    """
    queryset = Rule.objects.all()
    serializer_class = RuleSerializer
    ordering = ('sid',)
    ordering_fields = ('sid', 'category', 'msg', 'imported_date', 'updated_date')
    filter_fields = ('sid', 'category', 'msg', 'content')
    search_fields = ('sid', 'msg', 'content')

    @detail_route()
    def content(self, request, pk):
        rule = self.get_object()
        rulesets = Ruleset.objects.filter(categories__rule=rule)
        res = {}

        for ruleset in rulesets:
            res[ruleset.pk] = rule.generate_content(ruleset)

        return Response(res)

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


class BaseTransformationViewSet(viewsets.ModelViewSet):
    def create(self, request, *args, **kwargs):
        kwargs['fields'] = dict(self._fields)
        kwargs['action_type'] = self._action_type

        comment = request.data.pop('comment', None)
        key = request.data.get('transfo_type')
        value = request.data.get('transfo_value')
        trans_ok = key in Transformation.AVAILABLE_MODEL_TRANSFO and value in Transformation.AVAILABLE_MODEL_TRANSFO[key]
        msg = ''

        if trans_ok is False:
            values = Transformation.AVAILABLE_MODEL_TRANSFO.get(key, None)
            if values is None:
                keys = Transformation.AVAILABLE_MODEL_TRANSFO.keys()
                msg = 'trans_key is not a known key. keys are "%s"' % ' / '.join(keys)
            else:
                msg = 'trans_value is not a known value for key "%s". values are "%s"' % (key, ' / '.join(values))
            return Response({'update': msg}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
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
        comment = request.data.pop('comment', None)
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

    def _update_or_partial_update(self, request, partial, *args, **kwargs):
        kwargs['fields'] = dict(self._fields)
        kwargs['action_type'] = self._action_type

        comment = request.data.pop('comment', None)
        key = request.data.get('transfo_type')
        value = request.data.get('transfo_value')
        trans_ok = key in Transformation.AVAILABLE_MODEL_TRANSFO and value in Transformation.AVAILABLE_MODEL_TRANSFO[key]
        msg = ''

        if trans_ok is False:
            values = Transformation.AVAILABLE_MODEL_TRANSFO.get(key, None)
            if values is None:
                keys = Transformation.AVAILABLE_MODEL_TRANSFO.keys()
                msg = 'trans_key is not a known key. keys are "%s"' % ' / '.join(keys)
            else:
                msg = 'trans_value is not a known value for key "%s". values are "%s"' % (key, ' / '.join(values))
            return trans_ok, msg

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.instance.clean()
        serializer.is_valid(raise_exception=True)

        # This save is used to have the new name if user has edited transfo
        serializer.save()

        fields = kwargs['fields']
        for key, value in dict(fields).iteritems():
            fields[key] = serializer.validated_data[value]

        fields['comment'] = comment_serializer.validated_data['comment']
        fields['action_type'] = kwargs['action_type']
        fields['user'] = request.user
        fields['transformation'] = '%s: %s' % (fields.pop('trans_type'), fields.pop('trans_value').title())

        UserAction.create(**fields)
        return trans_ok, msg


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
        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    ==== POST ====\n
    Create a ruleset ACTION transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "action", "transfo_value": "drop"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "action", "transfo_value": "reject"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "action", "transfo_value": "filestore"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "action", "transfo_value": "bypass"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "action", "transfo_value": "none"}'

    Create a ruleset TARGET transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "target", "transfo_value": "src"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "target", "transfo_value": "dst"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "target", "transfo_value": "auto"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "target", "transfo_value": "none"}'

    Create a ruleset TARGET transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "lateral", "transfo_value": "yes"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "lateral", "transfo_value": "auto"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "transfo_type": "lateral", "transfo_value": "no"}'

    ==== PATCH ====\n
    Patch a ruleset transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"transfo_type": "target", "transfo_value": "dst"}' 

        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"transfo_type": "target", "transfo_value": "auto"}' 

        ...

    ==== PUT ====\n
    Replace a ruleset transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"ruleset": <pk-ruleset>,  "transfo_type": "action", "transfo_value": "drop"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"ruleset": <pk-ruleset>,  "transfo_type": "target", "transfo_value": "src"}'

        ...

    ==== DELETE ====\n
    Delete a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rulesets/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X DELETE

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
        trans_ok, msg = self._update_or_partial_update(request, partial=False, *args, **kwargs)
        if trans_ok is False:
            return Response({'update': msg}, status=status.HTTP_400_BAD_REQUEST)
        return super(RulesetTransformationViewSet, self).update(request, partial=False, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        trans_ok, msg = self._update_or_partial_update(request, partial=True, *args, **kwargs)
        if trans_ok is False:
            return Response({'update': msg}, status=status.HTTP_400_BAD_REQUEST)
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
        curl -k https://x.x.x.x/rest/rules/transformations/categories/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    ==== POST ====\n
    Create a category ACTION transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "action", "transfo_value": "drop"}'

        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "action", "transfo_value": "reject"}'

        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "action", "transfo_value": "filestore"}'

        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "action", "transfo_value": "bypass"}'

        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "action", "transfo_value": "none"}'

    Create a category TARGET transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "target", "transfo_value": "src"}'

        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "target", "transfo_value": "dst"}'

        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "target", "transfo_value": "auto"}'

        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "target", "transfo_value": "none"}'

    Create a category TARGET transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "lateral", "transfo_value": "yes"}'

        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "lateral", "transfo_value": "auto"}'

        curl -k https://x.x.x.x/rest/rules/transformations/categories/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "lateral", "transfo_value": "no"}'

    ==== PATCH ====\n
    Patch a category transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/categories/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"transfo_type": "target", "transfo_value": "dst"}' 

        curl -k https://x.x.x.x/rest/rules/transformations/categories/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"transfo_type": "target", "transfo_value": "auto"}' 

        ...

    ==== PUT ====\n
    Replace a category transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/categories/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "action", "transfo_value": "drop"}'

        curl -k https://x.x.x.x/rest/rules/transformations/categories/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"ruleset": <pk-ruleset>, "category": <pk-category>, "transfo_type": "target", "transfo_value": "src"}'

        ...

    ==== DELETE ====\n
    Delete a category:\n
        curl -k https://x.x.x.x/rest/rules/transformations/categories/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X DELETE

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
        trans_ok, msg = self._update_or_partial_update(request, partial=False, *args, **kwargs)
        if trans_ok is False:
            return Response({'update': msg}, status=status.HTTP_400_BAD_REQUEST)
        return super(CategoryTransformationViewSet, self).update(request, partial=False, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        trans_ok, msg = self._update_or_partial_update(request, partial=True, *args, **kwargs)
        if trans_ok is False:
            return Response({'update': msg}, status=status.HTTP_400_BAD_REQUEST)
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
    Show a rule transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rules/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    ==== POST ====\n
    Create a rule ACTION transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "action", "transfo_value": "drop"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "action", "transfo_value": "reject"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "action", "transfo_value": "filestore"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "action", "transfo_value": "bypass"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "action", "transfo_value": "none"}'

    Create a rule TARGET transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "target", "transfo_value": "src"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "target", "transfo_value": "dst"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "target", "transfo_value": "auto"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "target", "transfo_value": "none"}'

    Create a rule TARGET transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "lateral", "transfo_value": "yes"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "lateral", "transfo_value": "auto"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rules/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "lateral", "transfo_value": "no"}'

    ==== PATCH ====\n
    Patch a rule transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rules/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"transfo_type": "target", "transfo_value": "dst"}' 

        curl -k https://x.x.x.x/rest/rules/transformations/rules/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"transfo_type": "target", "transfo_value": "auto"}' 

        ...

    ==== PUT ====\n
    Replace a rule transformation:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rules/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "action", "transfo_value": "drop"}'

        curl -k https://x.x.x.x/rest/rules/transformations/rules/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"ruleset": <pk-ruleset>, "rule": <sid-rule>, "transfo_type": "target", "transfo_value": "src"}'

        ...

    ==== DELETE ====\n
    Delete a rule:\n
        curl -k https://x.x.x.x/rest/rules/transformations/rules/<pk-transfo>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X DELETE

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
        trans_ok, msg = self._update_or_partial_update(request, partial=False, *args, **kwargs)
        if trans_ok is False:
            return Response({'update': msg}, status=status.HTTP_400_BAD_REQUEST)
        return super(RuleTransformationViewSet, self).update(request, partial=False, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        trans_ok, msg = self._update_or_partial_update(request, partial=True, *args, **kwargs)
        if trans_ok is False:
            return Response({'update': msg}, status=status.HTTP_400_BAD_REQUEST)
        return super(RuleTransformationViewSet, self).update(request, partial=True, *args, **kwargs)


class BaseSourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Source
        fields = ('pk', 'name', 'created_date', 'updated_date', 'method', 'datatype', 'uri', 'cert_verif',
                  'cats_count', 'rules_count',)
        read_only_fields = ('pk', 'created_date', 'updated_date', 'method', 'datatype', 'uri', 'cert_verif',
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
        comment = request.data.pop('comment', None)
        serializer = self.get_serializer(data=request.data)
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
        UserAction.create(
                action_type='delete_source',
                user=request.user,
                source=source
        )
        return super(BaseSourceViewSet, self).destroy(request, *args, **kwargs)

    def upload(self, request, pk):
        source = self.get_object()
        if source.method != 'local':
            msg = 'No upload is allowed. method is currently "%s"' % source.method
            return Response({'upload': msg}, status=status.HTTP_400_BAD_REQUEST)

        if not request.FILES.has_key('file'):
            msg = 'No file to upload'
            return Response({'upload': msg}, status=status.HTTP_400_BAD_REQUEST)

        try:
            source.handle_uploaded_file(request.FILES['file'])
        except Exception as error:
            raise ServiceUnavailableException(error)
            return Response({'upload': error.message}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'upload': 'ok'}, status=200)

    @detail_route(methods=['post'])
    def update_source(self, request, pk):
        comment = request.data.pop('comment', None)
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
                    msg = 'Can not launch update in asynchronous'
                    return Response({'update': msg}, status=status.HTTP_400_BAD_REQUEST)
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
            return Response({'update': msg}, status=status.HTTP_400_BAD_REQUEST)

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
        except:
            raise ServiceUnavailableException()
        return Response(public_sources['sources'])

    @list_route(methods=['get'])
    def fetch_list_sources(self, request):
        try:
            fetch_public_sources()
        except:
            raise ServiceUnavailableException()
        return Response({'fetch': 'ok'})

    @detail_route(methods=['post'])
    def test(self, request, pk):
        comment = request.data.pop('comment', None)
        source = self.get_object()

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        sources_at_version = SourceAtVersion.objects.filter(source=source, version='HEAD')
        res = sources_at_version[0].test()

        if 'status' in res and res['status'] is True:
            del res['status']
            res['test'] = 'ok'

        if 'errors' in res and len(res['errors']) == 0:
            del res['errors']
            return Response(res)

        return Response(res, status=status.HTTP_400_BAD_REQUEST)


class PublicSourceSerializer(BaseSourceSerializer):
    public_source = serializers.CharField(required=True)

    class Meta(BaseSourceSerializer.Meta):
        model = BaseSourceSerializer.Meta.model
        fields = BaseSourceSerializer.Meta.fields + ('public_source',)
        read_only_fields = BaseSourceSerializer.Meta.read_only_fields + ('public_source',)

    def create(self, validated_data):
        source_name = validated_data['public_source']

        try:
            public_sources = get_public_sources(False)
        except:
            raise ServiceUnavailableException()

        if source_name not in public_sources['sources']:
            raise exceptions.NotFound(detail='Unknown public source "%s"' % source_name)

        validated_data['uri'] = public_sources['sources'][source_name]['url']
        validated_data['datatype'] = public_sources['sources'][source_name]['datatype']
        validated_data['method'] = 'http'
        validated_data['public_source'] = source_name
        instance = super(PublicSourceSerializer, self).create(validated_data)

        return instance


class PublicSourceViewSet(BaseSourceViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    List available public sources:\n
        curl -k https://x.x.x.x/rest/rules/public_sources/list_sources/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Fetch sources list:
        curl -k https://x.x.x.x/rest/rules/public_sources/fetch_list_sources/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    ==== POST ====\n
    Create public source:\n
        curl -k https://x.x.x.x/rest/rules/public_sources/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"name": "sonic public source", "public_source": "oisf/trafficid"}'

    Update public source:\n
        curl -k https://x.x.x.x/rest/rules/public_sources/<pk-public-source>/update_source/\?async=true -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

        curl -k https://x.x.x.x/rest/rules/public_sources/<pk-public-source>/update_source/\?async=false -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Test public source:\n
        curl -k https://x.x.x.x/rest/rules/public_sources/<pk-public-source>/test/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    ==== DELETE ====\n
    Delete public source:\n
        curl -k https://x.x.x.x/rest/rules/public_sources/<pk-public-source>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X DELETE

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
        fields = BaseSourceSerializer.Meta.fields + ('method',)
        read_only_fields = BaseSourceSerializer.Meta.read_only_fields

    def create(self, validated_data):
        validated_data['public_source'] = None
        instance = super(SourceSerializer, self).create(validated_data)
        return instance


class SourceViewSet(BaseSourceViewSet):
    """
    =============================================================================================================================================================
    ==== POST ====\n
    Create custom source:\n
        curl -k https://x.x.x.x/rest/rules/sources/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"name": "sonic custom source", "method": "local", "datatype": "sigs"}'

    Update custom (only for {method: http}):\n
        curl -k https://x.x.x.x/rest/rules/sources/<pk-source>/update_source/\?async=true -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

        curl -k https://x.x.x.x/rest/rules/sources/<pk-source>/update_source/\?async=false -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Test custom source:\n
        curl -k https://x.x.x.x/rest/rules/sources/<pk-source>/test/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Upload rules (only for {method: local}):\n
        curl -k https://x.x.x.x/rest/rules/sources/<pk-source>/upload/ -H 'Authorization: Token <token>' --keepalive-time 20 -F file=@/tmp/emerging.rules.tar.gz  -X POST

    ==== DELETE ====\n
    Delete custom source:\n
        curl -k https://x.x.x.x/rest/rules/sources/<pk-source>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X DELETE

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


router = DefaultRouter()
router.register('rules/ruleset', RulesetViewSet)
router.register('rules/category', CategoryViewSet)
router.register('rules/rule', RuleViewSet)
router.register('rules/sources', SourceViewSet, base_name='source')
router.register('rules/public_sources', PublicSourceViewSet, base_name='publicsource')
router.register('rules/transformations/rulesets', RulesetTransformationViewSet)
router.register('rules/transformations/categories', CategoryTransformationViewSet)
router.register('rules/transformations/rules', RuleTransformationViewSet)
