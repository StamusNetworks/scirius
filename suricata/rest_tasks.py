from drf_spectacular.utils import extend_schema
import suricata.tasks

from django.db.models import Case, When, BooleanField
from django.db.models.functions import Greatest
from django.utils import timezone
from rest_framework import serializers, viewsets, mixins, views
from rest_framework.decorators import action
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rules.models.model import Ruleset
from suricata.models import CeleryTask, CeleryTaskResult, RecurrentTask
from typing import ClassVar


class CeleryTaskResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = CeleryTaskResult
        fields = "__all__"
        read_only_fields = (
            "pk",
            "status",
            "task",
        )


class RecurrentTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecurrentTask
        fields = "__all__"
        read_only_fields = (
            "pk",
            "task",
            "children",
            "scheduled",
        )

    def to_representation(self, instance):
        return instance.display()


@extend_schema(tags=["Task"])
class RecurrentTaskViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin, viewsets.GenericViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show all recurrent tasks:\n
        curl -k https://x.x.x.x/rest/suricata/recurrent_task/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"count":1,"next":null,"previous":null,"results":[{"scheduled":"2018-06-19T16:34:25.837452Z","recurrence":"daily","task":"UpdatePushRuleset","target":"Probe",
        "created":"2018-06-19T16:34:25.838041Z","pk":41,"title":"Ruleset update/push","task_options":"{\\"push\\": true, \\"update\\": true}","user":1}]}

    Show task detail:\n
        curl -k https://x.x.x.x/rest/suricata/recurrent_task/<task-pk>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"scheduled":"2018-06-19T16:34:25.837452Z","recurrence":"daily","task":"UpdatePushRuleset","target":"Probe",
        "created":"2018-06-19T16:34:25.838041Z","pk":41,"title":"Ruleset update/push","task_options":"{\\"push\\": true, \\"update\\": true}","user":1}

    ==== DELETE ====\n
    Remove a recurrent task:\n
        curl -k https://x.x.x.x/rest/suricata/recurrent_task/<task-pk>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """

    queryset = RecurrentTask.objects.all()
    serializer_class = RecurrentTaskSerializer
    ordering = ("-pk",)
    ordering_fields = ("status", "task", "user")
    filterset_fields = ("status", "task", "user")
    search_fields = ("status", "task", "user__username")
    permission_classes = [IsAuthenticated]

    @suricata.tasks.rest_tasks_permission_required(RecurrentTask)
    def list(self, request, queryset, *args, **kwargs):
        queryset = self.filter_queryset(queryset)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class CeleryTaskSerializer(serializers.ModelSerializer):
    results = CeleryTaskResultSerializer(required=False, many=True, source="celerytaskresult_set")

    class Meta:
        model = CeleryTask
        fields = "__all__"
        read_only_fields = (
            "pk",
            "title",
            "children",
        )
        extra_kwargs: ClassVar[dict[str, dict[str, str]]] = {
            "title": {"source": "task"},
        }
        extra_fields = ("results",)

    def get_field_names(self, declared_fields, info):
        # needed to show results in celery tasks
        expanded_fields = super().get_field_names(declared_fields, info)
        return list(expanded_fields) + list(self.Meta.extra_fields)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data.update(instance.display(full=True))
        data["pk"] = instance.pk
        data["user"] = instance.user.pk if instance.user else None

        for field in ("icon", "id", "is_recurrent"):
            if field in data:
                data.pop(field)

        return data


@extend_schema(tags=["Task"])
class CeleryTaskViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show all tasks:\n
        curl -k https://x.x.x.x/rest/suricata/task/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"count":4,"next":null,"previous":null,"results":[
        {"results":[{"id":6,"date":"2024-11-25T10:37:07.329946+01:00","status":"success","message":null,"retry_no":0,"task":5}],
        "celery_id":"deae6d90-1f73-4d4f-9592-3f71e844a376","task":"UpdateRuleset","task_options":"{\"ruleset_pk\": 1}","status":"finished","hidden":false,
        "fired":"2024-11-25T10:37:07.113974+01:00","eta":null,"finished":"2024-11-25T10:37:07.333497+01:00","created":"2024-11-25T10:37:06.878593+01:00","retry":1,
        "success":true,"run_from_command":false,"user":2,"rtask_parent":null,"children":[],"state":"SUCCESS","runtime":0,"retries":null,"eta_time":null,"created_time":"2024-11-25T09:37:06.878593Z",
        "start_time":"2024-11-25T09:37:07.113974Z","end_time":"2024-11-25T09:37:07.333497Z","can_edit":false,"title":"Update ruleset","target":"ruleset","pk":5},
        {"results":[{"id":4,"date":"2024-11-25T10:33:31.164120+01:00","status":"success","message":null,"retry_no":0,"task":3}],"celery_id":"03996563-39c5-4f85-ae31-548f95b852d2",
        "task":"RulesetRulesAnalysis","task_options":"{\"ruleset_pk\": 1}","status":"finished","hidden":false,"fired":"2024-11-25T10:33:20.439611+01:00","eta":null,
        "finished":"2024-11-25T10:33:31.167797+01:00","created":"2024-11-25T10:32:15.351820+01:00","retry":1,"success":true,"run_from_command":false,"user":2,"rtask_parent":null,
        "children":[],"state":"SUCCESS","runtime":10,"retries":null,"eta_time":null,"created_time":"2024-11-25T09:32:15.351820Z","start_time":"2024-11-25T09:33:20.439611Z",
        "end_time":"2024-11-25T09:33:31.167797Z","can_edit":false,"title":"Ruleset rules analysis","target":"ruleset","pk":3},
        {"results":[{"id":2,"date":"2024-11-25T10:33:20.372201+01:00",
        "status":"success","message":null,"retry_no":0,"task":2}],"celery_id":"244651e7-d1ec-4b05-b68b-92ef1d6af12b","task":"UpdateRuleset","task_options":"{\"ruleset_pk\": 1}",
        "status":"finished","hidden":false,"fired":"2024-11-25T10:32:15.452796+01:00","eta":null,"finished":"2024-11-25T10:33:20.375252+01:00","created":"2024-11-25T10:32:15.344314+01:00","retry":1,
        "success":true,"run_from_command":false,"user":2,"rtask_parent":null,"children":[3,4],"state":"SUCCESS","runtime":64,"retries":null,"eta_time":null,"created_time":"2024-11-25T09:32:15.344314Z",
        "start_time":"2024-11-25T09:32:15.452796Z","end_time":"2024-11-25T09:33:20.375252Z","can_edit":false,"title":"Update ruleset","target":"ruleset","pk":2},
        {"results":[{"id":1,"date":"2024-11-25T10:32:15.422375+01:00","status":"success","message":null,"retry_no":0,"task":1}],"celery_id":"c4d57ec1-a87c-4645-b819-89ddada1f228",
        "task":"UpdateGenerateRuleset","task_options":"{\"ruleset_pk\": 1, \"update\": true, \"generate\": true}","status":"revoked","hidden":true,"fired":"2024-11-25T10:32:15.332394+01:00",
        "eta":null,"finished":"2024-11-25T10:32:15.426704+01:00","created":"2024-11-25T10:32:15.012402+01:00","retry":1,"success":true,"run_from_command":false,"user":2,
        "rtask_parent":null,"children":[],"state":"REVOKED","runtime":null,"retries":null,"eta_time":null,"created_time":"2024-11-25T09:32:15.012402Z","start_time":"2024-11-25T09:32:15.332394Z",
        "end_time":"2024-11-25T09:32:15.426704Z","can_edit":false,"failed_msg":"","title":"Ruleset: update/generate","pk":1}]}

    Show task detail:\n
        curl -k https://x.x.x.x/rest/suricata/task/<task-pk>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Returns=:\n
        HTTP/1.1 200 OK
        {"results": [{"id": 1, "date": "2024-11-25T10:32:15.422375+01:00", "status": "success", "message": null, "retry_no": 0, "task": 1}],
        "celery_id": "c4d57ec1-a87c-4645-b819-89ddada1f228", "task": "UpdateGenerateRuleset", "task_options": "{\"ruleset_pk\": 1, \"update\": true, \"generate\": true}",
        "status": "revoked", "hidden": true, "fired": "2024-11-25T10:32:15.332394+01:00", "eta": null, "finished": "2024-11-25T10:32:15.426704+01:00",
        "created": "2024-11-25T10:32:15.012402+01:00", "retry": 1, "success": true, "run_from_command": false, "user": 2, "rtask_parent": null,
        "children": [], "state": "REVOKED", "runtime": null, "retries": null, "eta_time": null, "created_time": "2024-11-25T09:32:15.012402Z", "start_time": "2024-11-25T09:32:15.332394Z",
        "end_time": "2024-11-25T09:32:15.426704Z", "can_edit": false, "failed_msg": "", "title": "Ruleset: update/generate", "pk": 1}

    ==== POST ====\n
    Revoke a task:\n
        curl -k https://x.x.x.x/rest/suricata/task/<task-pk>/revoke/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"revoke":"ok"}
    =============================================================================================================================================================
    """

    queryset = CeleryTask.objects.filter(is_recurrent=False)
    serializer_class = RecurrentTaskSerializer
    ordering = ("-pk",)
    ordering_fields = ("status", "task", "user")
    filterset_fields = ("status", "task", "user")
    search_fields = ("status", "task", "user__username")
    permission_classes = [IsAuthenticated]

    @suricata.tasks.rest_tasks_permission_required(CeleryTask)
    def list(self, request, queryset, *args, **kwargs):
        # queryset is not default queryset
        # we need to give it same behavior
        queryset = queryset.annotate(
            date=Greatest('finished', 'eta', 'created'),
            firsts=Case(
                When(status='running', then=True),
                default=False,
                output_field=BooleanField()
            )
        ).order_by('-firsts', '-date')
        queryset = self.filter_queryset(queryset)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        task = get_object_or_404(self.get_queryset(), pk=pk)
        return Response(self.serializer_class(task).data)

    @action(detail=True, methods=["post"])
    @suricata.tasks.rest_tasks_permission_required(CeleryTask)
    def revoke(self, request, pk):
        task = self.get_object()
        task.revoke()
        return Response({"revoke": "ok"})


class SciriusTaskSerializer(serializers.Serializer):
    schedule = serializers.DateTimeField(required=False, write_only=True)
    recurrence = serializers.ChoiceField(choices=RecurrentTask.FREQUENCIES, required=False, write_only=True)

    TASK_NAME = None
    ALLOW_RECURRENCE = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def to_internal_value(self, data):
        return super().to_internal_value(data)

    def validate(self, data):
        data = super().validate(data)

        if not self.ALLOW_RECURRENCE and data.get("recurrence"):
            raise serializers.ValidationError({"recurrence": "This field cannot be specified"})
        return data

    def validate_schedule(self, value):
        if value < timezone.now():
            raise serializers.ValidationError("This value cannot be in the past")
        return value

    def spawn(self, request, **kwargs):
        if self.TASK_NAME is None:
            raise NotImplementedError("TASK_NAME must be overriden in children classes")

        self.is_valid(raise_exception=True)
        task = CeleryTask.spawn(
            self.TASK_NAME,
            schedule=self.validated_data.get("schedule"),
            recurrence=self.validated_data.get("recurrence"),
            user=request.user,
            **kwargs,
        )

        return Response({"task_pk": task.pk})


class SuricataUpdateGenerateRulesetSerializer(SciriusTaskSerializer):
    TASK_NAME = 'UpdateGenerateRuleset'
    ALLOW_RECURRENCE = False
    ruleset = serializers.PrimaryKeyRelatedField(queryset=Ruleset.objects.all())
    update = serializers.BooleanField()
    generate = serializers.BooleanField()


@extend_schema(tags=["Task", "Ruleset"])
class SuricataRulesetCeleryTaskViewSet(views.APIView):
    """
    =============================================================================================================================================================
    ==== POST ====\n
    Update and generate ruleset:\n
        curl -k https://x.x.x.x/rest/rules/ruleset/<ruleset-pk>/update_generate/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X POST -d '{"update": true, "generate": false}'

    Return:\n
        HTTP/1.1 200 OK
        {"task_pk": 22}
    =============================================================================================================================================================
    """
    REQUIRED_GROUPS: ClassVar[dict[str, tuple[str]]] = {
        'WRITE': ('rules.ruleset_update_push',),
    }

    def post(self, request, pk: int):
        ruleset = get_object_or_404(Ruleset.objects.all(), pk=pk)
        data = request.data.copy()
        data["ruleset"] = ruleset.pk
        serializer = SuricataUpdateGenerateRulesetSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        return serializer.spawn(
            request,
            ruleset_pk=serializer.validated_data.get('ruleset').pk,
            update=serializer.validated_data.get('update'),
            generate=serializer.validated_data.get('generate'),
        )
