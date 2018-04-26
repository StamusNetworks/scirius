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
        Source, SourceAtVersion, UserAction
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
    sources = serializers.PrimaryKeyRelatedField(queryset=SourceAtVersion.objects.all(), many=True)

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


class RulesetViewSet(viewsets.ModelViewSet):
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


class RulesetTransformationSerializer(serializers.ModelSerializer):

    class Meta:
        model = RulesetTransformation
        fields = ('pk', 'ruleset', 'transfo_type', 'transfo_value')
        extra_kwargs = {
            'ruleset': {'source': 'ruleset_transformation'},
            'transfo_type': {'source': 'key'},
            'transfo_value': {'source': 'value'},
        }


class RulesetTransformationViewSet(viewsets.ModelViewSet):
    queryset = RulesetTransformation.objects.all()
    serializer_class = RulesetTransformationSerializer
    ordering = ('pk',)
    filter_fields = ('ruleset_transformation',)
    ordering_fields = ('ruleset_transformation',)

    def destroy(self, request, *args, **kwargs):
        transfo = self.get_object()
        comment = request.data.pop('comment', None)
        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
                action_type='delete_transform_ruleset',
                comment=comment_serializer.validated_data['comment'],
                user=request.user,
                transformation='%s: %s' % (transfo.key, transfo.value.title()),
                ruleset=transfo.ruleset_transformation
        )
        return super(RulesetTransformationViewSet, self).destroy(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        comment = request.data.pop('comment', None)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        ruleset = serializer.validated_data['ruleset_transformation']
        trans_type = serializer.validated_data['key']
        trans_value = serializer.validated_data['value']

        UserAction.create(
                action_type='transform_ruleset',
                comment=comment_serializer.validated_data['comment'],
                user=request.user,
                transformation='%s: %s' % (trans_type, trans_value.title()),
                ruleset=ruleset
        )

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def _update_or_partial_update(self, request, partial, *args, **kwargs):
        comment = request.data.pop('comment', None)

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # This save is used to have the new name if user has edited transfo
        serializer.save()

        trans_type = serializer.validated_data['key']
        trans_value = serializer.validated_data['value']
        ruleset = serializer.validated_data['ruleset_transformation']

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
                action_type='transform_ruleset',
                comment=comment_serializer.validated_data['comment'],
                user=request.user,
                transformation='%s: %s' % (trans_type, trans_value.title()),
                ruleset=ruleset
        )

    def update(self, request, pk, *args, **kwargs):
        self._update_or_partial_update(request, partial=False, *args, **kwargs)
        return super(RulesetTransformationViewSet, self).update(request, partial=False, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        self._update_or_partial_update(request, partial=True, *args, **kwargs)
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


class CategoryTransformationViewSet(viewsets.ModelViewSet):
    queryset = CategoryTransformation.objects.all()
    serializer_class = CategoryTransformationSerializer
    filter_fields = ('category_transformation', 'ruleset')
    ordering = ('pk',)
    ordering_fields = ('pk', 'ruleset', 'category_transformation')


class RuleTransformationSerializer(serializers.ModelSerializer):

    class Meta:
        model = RuleTransformation
        fields = ('pk', 'ruleset', 'rule', 'transfo_type', 'transfo_value')
        extra_kwargs = {
            'rule': {'source': 'rule_transformation'},
            'transfo_type': {'source': 'key'},
            'transfo_value': {'source': 'value'},
        }


class RuleTransformationViewSet(viewsets.ModelViewSet):
    queryset = RuleTransformation.objects.all()
    serializer_class = RuleTransformationSerializer
    filter_fields = ('rule_transformation', 'ruleset')
    ordering = ('pk',)
    ordering_fields = ('pk', 'ruleset', 'rule_transformation')


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
    queryset = Source.objects.filter(~Q(public_source=None))
    serializer_class = PublicSourceSerializer
    ordering = ('name',)
    ordering_fields = ('name', 'created_date', 'updated_date', 'cats_count', 'rules_count',)
    filter_fields = ('name', 'method')
    search_fields = ('name', 'method')

    @detail_route(methods=['post'])
    def upload(self, request, pk):
        return super(PublicSourceViewSet, self).upload(request, pk)


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
    queryset = Source.objects.filter(Q(public_source=None))
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
# router.register('rules/transformations/rulesets', RulesetTransformationViewSet)
# router.register('rules/transformations/categories', CategoryTransformationViewSet)
# router.register('rules/transformations/rules', RuleTransformationViewSet)
