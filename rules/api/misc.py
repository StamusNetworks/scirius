from collections import OrderedDict

from django.conf import settings
from django_filters import rest_framework as filters
from drf_spectacular.utils import extend_schema
from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter
from rest_framework.mixins import RetrieveModelMixin, UpdateModelMixin
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from rules.models.misc import DeepLink, DeepLinkEntity, SystemSettings, get_system_settings
from rules.models.model import UserAction, UserActionObject
from scirius.rest_utils import (
    SciriusModelViewSet,
    SciriusReadOnlyModelViewSet,
)
from scirius.settings import (
    CYBERCHEF_URL,
    ELASTICSEARCH_KEYWORD,
    KIBANA_PROXY,
    KIBANA_URL,
    USE_CYBERCHEF,
    USE_EVEBOX,
    USE_KIBANA,
)
from scirius.utils import get_middleware_module

from .common import CommentSerializer, ListFilter

Probe = __import__(settings.RULESET_MIDDLEWARE)


class SystemSettingsSerializer(serializers.ModelSerializer):
    use_arkime = serializers.BooleanField(read_only=True)
    use_opensearch = serializers.SerializerMethodField()
    arkime_url = serializers.CharField(read_only=True)

    def to_representation(self, data):
        data = super().to_representation(data)
        data.pop("elasticsearch_pass")
        return data

    def get_use_opensearch(self, instance):
        return instance.__class__.use_opensearch()

    class Meta:
        model = SystemSettings
        fields = "__all__"
        read_only_fields = ("kibana", "kibana_url", "evebox", "evebox_url", "cyberchef", "cyberchef_url")


@extend_schema(tags=["ES", "Settings"])
class SystemSettingsViewSet(UpdateModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show system settings:\n
        curl -k https://x.x.x.x/rest/rules/system_settings/1/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    ==== PUT/PATCH ====\n
        curl -k https://x.x.x.x/rest/rules/system_settings/1/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"use_http_proxy":false,"http_proxy":"","https_proxy":"","custom_elasticsearch":false,"elasticsearch_url":"http://elasticsearch:9200/"}'
        curl -k https://x.x.x.x/rest/rules/system_settings/1/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"use_http_proxy":false,"http_proxy":"","https_proxy":"","custom_elasticsearch":false,"elasticsearch_url":"http://elasticsearch:9200/"}'

    Return:\n
        HTTP/1.1 200 OK
        {"id":1,"use_http_proxy":false,"http_proxy":"","https_proxy":"","custom_elasticsearch":false,"elasticsearch_url":"http://elasticsearch:9200/"}

    =============================================================================================================================================================
    """

    serializer_class = SystemSettingsSerializer
    queryset = SystemSettings.objects.all()
    REQUIRED_GROUPS = {
        "READ": ("rules.configuration_view", "rules.events_view"),
        "WRITE": ("rules.configuration_edit",),
    }
    no_tenant_check = True

    def retrieve(self, request, pk=None):
        instance = self.get_object()
        serializer = SystemSettingsSerializer(instance)
        data = serializer.data.copy()

        data["kibana"] = USE_KIBANA
        data["evebox"] = USE_EVEBOX
        data["es_keyword"] = ELASTICSEARCH_KEYWORD

        if USE_KIBANA:
            if KIBANA_PROXY:
                data["kibana_url"] = "/kibana"
            else:
                data["kibana_url"] = KIBANA_URL

        if USE_EVEBOX:
            data["evebox_url"] = "/evebox"

        data["cyberchef"] = USE_CYBERCHEF
        if USE_CYBERCHEF:
            data["cyberchef_url"] = CYBERCHEF_URL

        get_middleware_module("common").update_settings(data)
        return Response(data)

    def get_object(self):
        return get_system_settings()

    def _update_or_partial_update(self, request):
        data = request.data.copy()
        comment = data.pop("comment", None)

        # because of rest website UI
        if isinstance(comment, list):
            comment = comment[0]

        comment_serializer = CommentSerializer(data={"comment": comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
            action_type="system_settings", comment=comment_serializer.validated_data["comment"], request=request
        )

    def update(self, request, *args, **kwargs):
        self._update_or_partial_update(request)
        return super(SystemSettingsViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        self._update_or_partial_update(request)
        return super(SystemSettingsViewSet, self).update(request, partial=True, *args, **kwargs)


class SciriusContextAPIView(APIView):
    REQUIRED_GROUPS = {
        "READ": ("rules.configuration_view", "rules.events_view"),
    }
    no_tenant_check = True

    def get(self, request, format=None):
        context = get_middleware_module("common").get_homepage_context()
        return Response(context)


class UserActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAction
        fields = ("pk", "action_type", "date", "comment", "user", "username", "ua_objects", "client_ip")

    def to_representation(self, instance):
        data = super(UserActionSerializer, self).to_representation(instance)
        actions_dict = get_middleware_module("common").get_user_actions_dict()

        all_content = {}
        format_ = {"user": instance.username, "datetime": instance.date}
        for ua_obj in UserActionObject.objects.filter(user_action=instance):
            content = {}

            # build description
            format_[ua_obj.action_key] = ua_obj.action_value

            # Transformation has None type
            if ua_obj.content_type is not None:
                klass = ua_obj.content_type.model_class()
                content["type"] = klass.__name__

                # Check existance of content_object
                sub_instances = klass.objects.filter(pk=ua_obj.object_id)
                if sub_instances.count() > 0:
                    if klass.__name__ != "Rule":
                        content["pk"] = ua_obj.object_id
                    else:
                        content["sid"] = ua_obj.object_id

            content["value"] = ua_obj.action_value
            all_content[ua_obj.action_key] = content

        data["title"] = instance.get_title()
        data["description_raw"] = (
            actions_dict[instance.action_type]["description"] if instance.action_type is not None else None
        )
        data["description"] = (
            actions_dict[instance.action_type]["description"].format(**format_)
            if instance.description is None
            else instance.description
        )
        data["ua_objects"] = all_content

        return data


class UserActionDateOrderingFilter(OrderingFilter):
    def filter_queryset(self, request, queryset, view):
        ordering = self.get_ordering(request, queryset, view)

        if "date" not in ordering or "-date" not in ordering:
            ordering += ("-date",) if isinstance(ordering, tuple) else ["-date"]
        return queryset.order_by(*ordering)


class UserActionFilter(filters.FilterSet):
    min_date = filters.DateFilter(field_name="date", lookup_expr="gte")
    max_date = filters.DateFilter(field_name="date", lookup_expr="lte")
    comment = ListFilter(field_name="comment", lookup_expr="icontains")
    client_ip = filters.CharFilter(field_name="client_ip", lookup_expr="exact")

    class Meta:
        model = UserAction
        fields = [
            "username",
            "date",
            "action_type",
            "comment",
            "client_ip",
            "user_action_objects__action_key",
            "user_action_objects__action_value",
        ]


@extend_schema(tags=["User action"])
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
    ordering = ("-pk",)
    ordering_fields = ("pk", "date", "username", "action_type", "client_ip")
    filterset_class = UserActionFilter
    filter_backends = (filters.DjangoFilterBackend, UserActionDateOrderingFilter)
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        actions_type = UserAction.get_allowed_actions_type(self.request)
        history = UserAction.objects.filter(action_type__in=actions_type)
        user = self.request.user
        if user.__class__.__name__ != "FakeUser":
            history |= UserAction.objects.filter(user=user)
        return history

    @action(detail=False, methods=["get"])
    def get_action_type_list(self, request):
        actions_dict = get_middleware_module("common").get_user_actions_dict()

        res = OrderedDict()
        for key, value in actions_dict.items():
            res.update({key: value["title"]})

        return Response({"action_type_list": res})


class DeepLinkEntitySerializer(serializers.ModelSerializer):
    class Meta:
        model = DeepLinkEntity
        fields = ("name",)


class DeepLinkSerializer(serializers.ModelSerializer):
    entities = DeepLinkEntitySerializer(many=True)

    class Meta:
        model = DeepLink
        fields = ("pk", "name", "template", "all", "entities")

    def update(self, instance, validated_data):
        entities_data = validated_data.get("entities", [])
        instance.all = validated_data.get("all", instance.all)

        instance.name = validated_data.get("name", instance.name)
        instance.template = validated_data.get("template", instance.template)
        instance.save()

        entity_names = [data["name"] for data in entities_data if data.get("name", None)]
        entities = []
        for name in entity_names:
            entity, _ = DeepLinkEntity.objects.get_or_create(name=name)
            entities.append(entity)
        instance.entities.set(entities)

        return instance

    def create(self, validated_data):
        entities = validated_data.pop("entities", None)
        deeplink = DeepLink.objects.create(**validated_data)
        if entities:
            for entity_data in entities:
                entity, _ = DeepLinkEntity.objects.get_or_create(**entity_data)
                deeplink.entities.add(entity)
        return deeplink


@extend_schema(tags=["Deep link"])
class DeepLinkViewSet(SciriusModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    List all links:\n
        curl -k -v https://x.x.x.x/rest/rules/deeplink/?ordering=all&page_size=1 -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"count":2,"next":null,"previous":null,"results":[{"pk":4,"name":"google","template":"http://google.com/search/{{ value }}","all":false,"entities":[]},{"pk":3,"name":"google2","template":"https://google2.com/search/{{ value }}","all":false,"entities":[{"name":"ip"}]}]}

    Get a link:\n
        curl -k -v https://x.x.x.x/rest/rules/deeplink/<pk>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":4,"name":"google","template":"http://google.com/search/{{ value }}","all":false,"entities":[]}

    ==== POST ====\n
    Create a new link:\n
        curl -k -v https://myssp/rest/rules/deeplink/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"name": "duckduckgo", "template": "http://duckduckgo.com/search/{{ value }}", "entities": [{"name": "ip"}, {"name": "port"}]}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":5,"name":"duckduckgo","template":"http://duckduckgo.com/search/{{ value }}","all":false,"entities":[{"name":"ip"},{"name":"port"}]}

    ==== PUT ====\n
    Update a link and its entities:\n
        curl -k -v https://x.x.x.x/rest/rules/deeplink/<pk>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X PUT -d '{"name": "yahoo", "template": "https://yahoo.com/search/{{ value }}", "entities": [{"name": "port"}], "all": false}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":3,"name":"yahoo","template":"https://yahoo.com/search/{{ value }}","all":false,"entities":[{"name":"port"}]}

    ==== PATCH ====\n
    Partial update a link:\n
        curl -k -v https://myssp/rest/rules/deeplink/<pk>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X PATCH -d '{"name": "google1"}'

    Return:\n
        HTTP/1.1 200 OK
        {"pk":4,"name":"google1","template":"http://google.com/search/{{ value }}","all":false,"entities":[]}&

    ==== DELETE ====\n
    Delete a link:\n
        curl -k -v https://myssp/rest/rules/deeplink/<pk>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """

    queryset = DeepLink.objects.all()
    serializer_class = DeepLinkSerializer
    ordering = ("name",)
    filterset_fields = ("name", "template", "all", "entities__name")
    ordering_fields = ("pk", "name", "template", "all", "entities__name")

    REQUIRED_GROUPS = {
        "READ": ("rules.events_view",),
        "WRITE": ("rules.configuration_edit",),
    }
    no_tenant_check = True
