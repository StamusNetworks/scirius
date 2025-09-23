import contextlib

from django.conf import settings
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.validators import UniqueValidator

from rules.models.model import Category, Ruleset, Source
from rules.models.model import UserAction
from scirius.utils import get_middleware_module
from suricata.rest_tasks import SciriusTaskSerializer

from .common import CommentSerializer

Probe = __import__(settings.RULESET_MIDDLEWARE)


class CopyRulesetSerializer(serializers.Serializer):
    name = serializers.CharField(
        required=True, allow_blank=False, validators=[UniqueValidator(queryset=Ruleset.objects.all())]
    )


class RulesetSerializer(serializers.ModelSerializer):
    sources = serializers.PrimaryKeyRelatedField(queryset=Source.objects.all(), many=True, required=False)
    categories = serializers.PrimaryKeyRelatedField(queryset=Category.objects.all(), many=True, required=False)
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True, allow_null=True)
    warnings = serializers.CharField(required=False, allow_blank=True, read_only=True, allow_null=True)

    class Meta:
        model = Ruleset
        fields = (
            "pk",
            "name",
            "descr",
            "created_date",
            "updated_date",
            "validity",
            "errors",
            "rules_count",
            "sources",
            "categories",
            "comment",
            "warnings",
        )
        read_only_fields = ("pk", "created_date", "updated_date", "validity", "errors", "rules_count", "warnings")

    def create(self, validated_data):
        validated_data["created_date"] = timezone.now()
        validated_data["updated_date"] = timezone.now()
        instance = super(RulesetSerializer, self).create(validated_data)
        return instance

    def to_representation(self, instance):
        data = super(RulesetSerializer, self).to_representation(instance)
        sources = instance.sources.all()
        data["sources"] = [source.pk for source in sources]

        with contextlib.suppress(AttributeError):
            data.update(get_middleware_module("common").get_rest_ruleset(instance))
        return data


class RulesetUpdateTaskSerializer(SciriusTaskSerializer):
    TASK_NAME = "UpdateRuleset"
    ALLOW_RECURRENCE = True
    ruleset = serializers.PrimaryKeyRelatedField(queryset=Ruleset.objects.all())


@extend_schema(tags=["Ruleset"])
class RulesetViewSet(viewsets.ModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Ruleset detail:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":9,"name":"MyCreatedRuleset","descr":"","created_date":"2018-05-04T16:10:43.698843+02:00","updated_date":"2018-05-04T16:10:43.698852+02:00","validity":true,"errors":"\\"\\"","rules_count":204,"sources":[1],"categories":[27]}

    ==== POST ====\n
    Create a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"name": "SonicRuleset", "sources": [pk-source1, ..., pk-sourceN], "categories": [pk-category1, ..., pk-categoryN]}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":12,"name":"SonicRuleset","descr":"","created_date":"2018-05-07T11:27:21.482840+02:00","updated_date":"2018-05-07T11:27:21.482853+02:00","validity":true,"errors":"","rules_count":0,"sources":[1],"categories":[27]}

    Copy a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/copy/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST  -d '{"name": "copyRuleset1", "comment": "need a clone"}'

    Return:\n
        HTTP/1.1 200 OK
        {"copy":"ok"}

    Update ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/update_ruleset/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/update_ruleset/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"schedule": "2024-10-30T17:00"}'

    Return:\n
        HTTP/1.1 200 OK
        {"task_pk": 268}

    ==== PATCH ====\n
    Patch a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"name": "PatchedSonicRuleset", "categories": [pk-category1, ..., pk-categoryN]}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":12,"name":"SonicRulesetPatched","descr":"","created_date":"2018-05-07T11:27:21.482840+02:00","updated_date":"2018-05-07T11:27:21.482853+02:00","validity":true,"errors":"\\"\\"","rules_count":204,"sources":[1],"categories":[27,1]}

    ==== PUT ====\n
    Replace a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"name": "ReplacedSonicRuleset", "comment": "sonic comment", "sources": [pk-source1, ..., pk-sourceN, "categories": [pk-category1, ..., pk-categoryN]}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":12,"name":"SonicRulesetReplaced","descr":"","created_date":"2018-05-07T11:27:21.482840+02:00","updated_date":"2018-05-07T11:27:21.482853+02:00","validity":true,"errors":"\\"\\"","rules_count":204,"sources":[1],"categories":[1]}

    ==== DELETE ====\n
    Delete a ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<pk-ruleset>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """

    queryset = Ruleset.objects.all()
    serializer_class = RulesetSerializer
    ordering = ("name",)
    ordering_fields = ("name", "created_date", "updated_date", "rules_count")
    filterset_fields = ("name", "descr")
    REQUIRED_GROUPS = {
        "READ": ("rules.source_view",),
        "WRITE": ("rules.source_edit",),
    }
    no_tenant_check = True

    def _validate_categories(self, sources, categories):
        if len(sources) == 0 and len(categories) > 0:
            msg = "No source selected or wrong selected source(s). Cannot add categories without their source."
            raise serializers.ValidationError({"sources": [msg]})
        elif len(sources) > 0 and len(categories) > 0:
            for category in categories:
                if category.source not in sources:
                    msg = "One or more of categories is/are not in selected sources."
                    raise serializers.ValidationError({"categories": [msg]})

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        comment = data.pop("comment", None)

        # because of rest website UI
        if isinstance(comment, list):
            comment = comment[0]

        serializer = RulesetSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        sources = serializer.validated_data.get("sources", [])
        categories = serializer.validated_data.get("categories", [])
        self._validate_categories(sources, categories)

        serializer.save()
        serializer.instance.number_of_rules()

        comment_serializer = CommentSerializer(data={"comment": comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
            action_type="create_ruleset",
            comment=comment_serializer.validated_data["comment"],
            request=request,
            ruleset=serializer.instance,
        )

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        ruleset = self.get_object()
        comment = request.data.get("comment", None)
        comment_serializer = CommentSerializer(data={"comment": comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
            action_type="delete_ruleset",
            request=request,
            ruleset=ruleset,
            comment=comment_serializer.validated_data["comment"],
        )
        return super(RulesetViewSet, self).destroy(request, *args, **kwargs)

    def _update_or_partial_update(self, request, partial):
        comment = request.data.get("comment", None)

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        sources = instance.sources.all()
        if "sources" in serializer.validated_data:
            sources = serializer.validated_data["sources"]

        categories = instance.categories.all()
        if "categories" in serializer.validated_data:
            categories = serializer.validated_data["categories"]

        self._validate_categories(sources, categories)

        # This save is used to have the new name if user has edited ruleset name
        serializer.save()
        instance.number_of_rules()

        comment_serializer = CommentSerializer(data={"comment": comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
            action_type="edit_ruleset",
            comment=comment_serializer.validated_data["comment"],
            request=request,
            ruleset=instance,
        )

    def update(self, request, *args, **kwargs):
        self._update_or_partial_update(request, False)
        return super(RulesetViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        self._update_or_partial_update(request, True)
        return super(RulesetViewSet, self).update(request, partial=True, *args, **kwargs)

    @action(detail=True, methods=["post"])
    def copy(self, request, pk):
        data = request.data.copy()
        ruleset = self.get_object()

        comment = data.pop("comment", None)
        copy_serializer = CopyRulesetSerializer(data=data)
        copy_serializer.is_valid(raise_exception=True)

        ruleset.copy(copy_serializer.validated_data["name"])

        UserAction.create(action_type="copy_ruleset", comment=comment, request=request, ruleset=ruleset)

        return Response({"copy": "ok"})

    @action(detail=True, methods=["get"])
    def rules_count(self, request, pk):
        ruleset = self.get_object()
        return Response(ruleset.number_of_rules())

    @action(detail=True, methods=["post"])
    def update_ruleset(self, request, pk):
        ruleset = self.get_object()
        data = request.data.copy()
        data["ruleset"] = ruleset.pk
        return RulesetUpdateTaskSerializer(data=data).spawn(request, ruleset_pk=ruleset.pk)
