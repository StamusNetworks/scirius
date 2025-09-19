from django.conf import settings
from drf_spectacular.utils import extend_schema
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.response import Response

from rules.models import Category, Ruleset
from scirius.rest_utils import SciriusReadOnlyModelViewSet

Probe = __import__(settings.RULESET_MIDDLEWARE)


class CategoryChangeSerializer(serializers.Serializer):
    ruleset = serializers.PrimaryKeyRelatedField(queryset=Ruleset.objects.all(), write_only=True)
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True)


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ("pk", "name", "descr", "created_date", "source")


@extend_schema(tags=["Source"])
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
    ordering = ("name",)
    ordering_fields = ("pk", "name", "created_date", "source")
    filterset_fields = ("name", "source")
    REQUIRED_GROUPS = {
        "READ": ("rules.ruleset_policy_view",),
        "WRITE": ("rules.ruleset_policy_edit",),
    }

    @action(detail=True, methods=["post"])
    def enable(self, request, pk):
        category = self.get_object()
        serializer = CategoryChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        category.enable(serializer.validated_data["ruleset"], request, serializer.validated_data.get("comment", None))
        return Response({"enable": "ok"})

    @action(detail=True, methods=["post"])
    def disable(self, request, pk):
        category = self.get_object()
        serializer = CategoryChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        category.disable(serializer.validated_data["ruleset"], request, serializer.validated_data.get("comment", None))
        return Response({"disable": "ok"})

    def get_serializer_class(self):
        if self.action in ("enable", "disable"):
            return CategoryChangeSerializer
        return CategorySerializer
