import json
from typing import Any

from django.conf import settings
from django.db import models
from drf_spectacular.utils import extend_schema
from rest_framework import serializers, status, viewsets
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from rules.models.filter_sets import FilterSet
from scirius.utils import get_middleware_module


class FilterSetSerializer(serializers.ModelSerializer):
    class Meta:
        model = FilterSet
        fields = "__all__"

    def to_internal_value(self, data: dict[str, Any]):
        try:
            if "content" in data:
                data["content"] = json.dumps(data["content"])
        except ValueError:
            raise serializers.ValidationError({"content": "Not a JSON format."})

        if not data.get("share", False):
            data["user"] = self.context["request"].user.pk

        return super().to_internal_value(data)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["content"] = json.loads(data["content"])
        data["share"] = "global" if data["user"] is None else "private"
        data.pop("user")

        # Work-around following #4388, to keep backward compatibility
        for _filter in data["content"]:
            if _filter["id"] == "search":
                _filter["id"] = "content"
        return data


@extend_schema(tags=["ES", "Filter"])
class FilterSetViewSet(viewsets.ModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Get :\n
    Show all filter sets (even static ones that have no pk):\n
        curl -k https://x.x.x.x/rest/rules/hunt_filter_sets/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        [{"id":1,"content":[{"id":"alert.tag","value":{"untagged":true,"relevant":true,"informational":true}},{"negated":false,"query":"rest","id":"hits_min","value":1,"label":"Alerts min: 1"},
        {"negated":false,"query":"rest","id":"hits_max","value":10,"label":"Alerts max: 10"},
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
    ordering = ("name",)
    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
        "WRITE": ("rules.events_view",),
    }
    no_tenant_check = True

    def get_queryset(self):
        user = self.request.user
        Q = models.Q
        if user.__class__.__name__ == "FakeUser" and settings.DEBUG:
            return FilterSet.objects.filter(user=None)
        return FilterSet.objects.filter(Q(user=user) | Q(user=None))

    @staticmethod
    def _sort_filtersets(item):
        return item["name"]

    def list(self, request):
        filters = get_middleware_module("common").get_default_filter_sets()

        queryset = self.get_queryset()
        serializer = FilterSetSerializer(queryset, many=True)
        filters = serializer.data + filters
        filters = sorted(filters, key=self._sort_filtersets)
        return Response(filters)

    def create(self, request, *args, **kwargs):
        data = request.data.copy()

        if data.get("share", False) and not request.user.has_perm("rules.events_edit"):
            raise PermissionDenied

        serializer = FilterSetSerializer(data=data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def update(self, request, *args, **kwargs):
        if request.data.get("share", False) and not request.user.has_perm("rules.events_edit"):
            raise PermissionDenied
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        if request.data.get("share", False) and not request.user.has_perm("rules.events_edit"):
            raise PermissionDenied
        return super().update(request, partial=True, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        if request.data.get("share", False) and not request.user.has_perm("rules.events_edit"):
            raise PermissionDenied
        return super().destroy(request, *args, **kwargs)
