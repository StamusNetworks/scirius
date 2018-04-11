from django.conf import settings
from rest_framework import serializers, viewsets, permissions
from rest_framework.decorators import detail_route
from rest_framework.response import Response
from rest_framework.routers import DefaultRouter

from rules.models import Rule, Category, Ruleset, RuleTransformation, CategoryTransformation, RulesetTransformation, Transformation, Source


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


class RulesetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ruleset
        fields = ('pk', 'name', 'descr', 'created_date', 'updated_date', 'need_test', 'validity', \
                'errors', 'rules_count')
        read_only_fields = ('pk', 'created_date', 'updated_date', 'need_test', 'validity', 'errors', \
                'rules_count')


class RulesetViewSet(viewsets.ModelViewSet):
    queryset = Ruleset.objects.all()
    serializer_class = RulesetSerializer
    ordering = ('name',)
    ordering_fields = ('name', 'created_date', 'updated_date', 'rules_count')
    filter_fields = ('name', 'descr')


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
        # rulesets = Ruleset.objects.all()
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
    filter_fields = ('ruleset_transformation',)
    ordering_fields = ('ruleset_transformation')


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
    ordering_fields = ('pk', 'ruleset', 'rule_transformation')


class SourceSerializer(serializers.ModelSerializer):

    class Meta:
        model = Source
        fields = ('pk', 'name', 'created_date', 'updated_date', 'method', 'datatype', 'uri', 'cert_verif', \
                  'number_of_categories', 'number_of_rules')
        read_only_fields = ('pk', 'created_date', 'updated_date', 'method', 'datatype', 'uri', 'cert_verif', \
                            'number_of_categories', 'number_of_rules')
        extra_kwargs = {
            'number_of_categories': {'source': 'cats_count'},
            'number_of_rules': {'source': 'rules_count'},
        }


class SourceViewSet(viewsets.ModelViewSet):
    queryset = Source.objects.all()
    serializer_class = SourceSerializer
    ordering = ('name',)
    ordering_fields = ('name', 'created_date', 'updated_date', 'cats_count', 'rules_count', 'method')
    filter_fields = ('name', 'method')
    search_fields = ('name', 'method')


router = DefaultRouter()
router.register('rules/ruleset', RulesetViewSet)
router.register('rules/category', CategoryViewSet)
router.register('rules/rule', RuleViewSet)
router.register('rules/source', SourceViewSet)
router.register('rules/transformations/rulesets', RulesetTransformationViewSet)
router.register('rules/transformations/categories', CategoryTransformationViewSet)
router.register('rules/transformations/rules', RuleTransformationViewSet)
