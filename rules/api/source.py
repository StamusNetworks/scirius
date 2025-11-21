import tempfile

from django.conf import settings
from drf_spectacular.utils import extend_schema
from rest_framework import exceptions, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework.response import Response

from rules.models.model import Source, SourceUpdate, UserAction
from rules.views.source import fetch_public_sources, get_public_sources
from scirius.utils import get_middleware_module
from suricata.rest_tasks import SciriusTaskSerializer

from .common import CommentSerializer

Probe = __import__(settings.RULESET_MIDDLEWARE)


class BaseSourceTaskSerializer(SciriusTaskSerializer):
    ALLOW_RECURRENCE = False
    source = serializers.PrimaryKeyRelatedField(queryset=Source.objects.all())

    def spawn(self, request, **kwargs):
        self.is_valid(raise_exception=True)
        return super().spawn(request, source_pk=self.validated_data.get("source").pk, **kwargs)


class SourceUpdateTaskSerializer(BaseSourceTaskSerializer):
    TASK_NAME = "SourceUpdateParentTask"
    ALLOW_RECURRENCE = True


class SourceRulesAnalysisTaskSerializer(BaseSourceTaskSerializer):
    TASK_NAME = "SourceRulesAnalysis"


class AddSourceTaskSerializer(BaseSourceTaskSerializer):
    TASK_NAME = "AddSourceTask"


class SourceTestTaskSerializer(BaseSourceTaskSerializer):
    TASK_NAME = "SourceTestTask"


class UploadSourceBaseTaskSerializer(BaseSourceTaskSerializer):
    path = serializers.CharField()

    def spawn(self, request):
        self.is_valid(raise_exception=True)
        return super().spawn(request, path=self.validated_data.get("path"))


class UploadAddSourceTaskSerializer(UploadSourceBaseTaskSerializer):
    TASK_NAME = "UploadAddSourceTask"


class UploadEditSourceTaskSerializer(UploadSourceBaseTaskSerializer):
    TASK_NAME = "UploadEditSourceTask"


class BaseSourceSerializer(serializers.ModelSerializer):
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True, allow_null=True)

    class Meta:
        model = Source
        fields = (
            "pk",
            "name",
            "created_date",
            "updated_date",
            "method",
            "datatype",
            "uri",
            "cert_verif",
            "use_iprep",
            "version",
            "use_sys_proxy",
            "untrusted",
        )
        read_only_fields = ("pk", "created_date", "updated_date", "method", "datatype", "cert_verif")

    def create(self, validated_data):
        validated_data["cert_verif"] = True
        return super().create(validated_data)


@extend_schema(tags=["Source"])
class BaseSourceViewSet(viewsets.ModelViewSet):
    REQUIRED_GROUPS = {
        "READ": ("rules.source_view",),
        "WRITE": ("rules.source_edit",),
    }

    def _process_action(self, request, serializer_class):
        """
        Because the code is the same for starting tasks, we use this generic function.

        :param request: HTTP request object
        :param serializer_class: class used toserialize data from request.data

        :return: HTTP Response from the inherited spawn method
        """
        data = request.data.copy()

        source = self.get_object()
        data["source"] = source.pk
        serializer = serializer_class(data=data)
        return serializer.spawn(request)

    def create(self, request, *args, **kwargs):
        """
        Create a new source without performing any operation on itself. You'll need to call /update/ or /upload/ to
        start the task in order to have rules in it.
        """
        data = request.data.copy()
        comment = data.pop("comment", None)

        # because of rest website UI
        if isinstance(comment, list):
            comment = comment[0]

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        comment_serializer = CommentSerializer(data={"comment": comment})
        comment_serializer.is_valid(raise_exception=True)
        source = serializer.instance

        UserAction.create(
            action_type="create_source",
            comment=comment_serializer.validated_data["comment"],
            request=request,
            source=source,
        )

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        source = self.get_object()
        # Do not need to copy 'request.data' and pop 'comment'
        # because we are not using serializer there
        comment = request.data.get("comment", None)
        comment_serializer = CommentSerializer(data={"comment": comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
            action_type="delete_source",
            request=request,
            source=source,
            comment=comment_serializer.validated_data["comment"],
        )
        return super(BaseSourceViewSet, self).destroy(request, *args, **kwargs)

    def upload(self, request, pk):
        """
        Upload a source file and start related Celery tasks

        Route only available for local sources.
        """
        source = self.get_object()

        comment_serializer = CommentSerializer(data=request.data)
        comment_serializer.is_valid(raise_exception=True)

        if source.method != "local":
            msg = 'No upload is allowed. method is currently "%s"' % source.method
            raise serializers.ValidationError({"upload": [msg]})

        if "file" not in request.FILES:
            raise serializers.ValidationError({"file": ["This field is required."]})

        path = None
        file_ = request.FILES["file"]
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            for chunk in file_.chunks():
                tmpfile.write(chunk)
            path = tmpfile.name

        # because in REST we are creating the source without handling file and not running any task, it is an
        # EditSource here with the uploaded file
        TaskSerializer = UploadEditSourceTaskSerializer
        serializer = TaskSerializer(data={"source": source.pk, "path": path})
        result = serializer.spawn(request)

        UserAction.create(
            action_type="upload_source",
            comment=comment_serializer.validated_data.get("comment"),
            request=request,
            source=source,
        )

        return result

    @action(detail=True, methods=["post"])
    def update_source(self, request, pk):
        """
        Method only available for web sources (fetch them from HTTP/HTTPS).
        """
        # Do not need to copy 'request.data' and pop 'comment'
        # because we are not using serializer there
        comment = request.data.get("comment", None)

        source = self.get_object()
        if source.method != "http":
            raise serializers.ValidationError(
                {"update": "Operation only available for web sources, use /upload/ instead"}
            )
        comment_serializer = CommentSerializer(data={"comment": comment})
        comment_serializer.is_valid(raise_exception=True)

        serializer = SourceUpdateTaskSerializer(data={"source": source.pk})

        task = serializer.spawn(request)
        UserAction.create(
            action_type="update_source",
            comment=comment_serializer.validated_data["comment"],
            request=request,
            source=source,
        )
        return task

    @action(detail=False, methods=["get"])
    def list_sources(self, request):
        try:
            public_sources = get_public_sources(False)
        except Exception as e:
            raise serializers.ValidationError({"list": [str(e)]})
        return Response(public_sources["sources"])

    @action(detail=False, methods=["get"])
    def fetch_list_sources(self, request):
        try:
            fetch_public_sources()
        except Exception as e:
            raise serializers.ValidationError({"fetch": [str(e)]})
        return Response({"fetch": "ok"})

    @action(detail=True, methods=["post"])
    def rules_analysis(self, request, pk):
        """
        Start the analysis of a source.

        The source needs to be updated first!
        """
        source = self.get_object()
        if source.updated_date is None:
            raise serializers.ValidationError({"analysis": ["Source needs to be updated first"]})
        return self._process_action(request, SourceRulesAnalysisTaskSerializer)

    @action(detail=True, methods=["post"])
    def test(self, request, pk):
        """
        Start the test of a source.

        The source needs to be updated first!
        """
        source = self.get_object()
        if source.updated_date is None:
            raise serializers.ValidationError({"test": ["Source needs to be updated first"]})
        return self._process_action(request, SourceTestTaskSerializer)


class PublicSourceSerializer(BaseSourceSerializer):
    public_source = serializers.CharField(required=True)
    secret_code = serializers.CharField(required=False)

    class Meta(BaseSourceSerializer.Meta):
        model = BaseSourceSerializer.Meta.model
        fields = BaseSourceSerializer.Meta.fields + ("public_source", "secret_code", "comment")
        read_only_fields = BaseSourceSerializer.Meta.read_only_fields + ("public_source", "uri")

    def create(self, validated_data):
        source_name = validated_data["public_source"]

        try:
            public_sources = get_public_sources(False)
        except Exception as e:
            raise serializers.ValidationError({"list": [str(e)]})

        if source_name not in public_sources["sources"]:
            raise exceptions.NotFound(detail='Unknown public source "%s"' % source_name)

        uri = public_sources["sources"][source_name]["url"]
        if "secret-code" not in uri:
            if "secret_code" in validated_data:
                raise serializers.ValidationError({"secret_code": ["No secret code needed"]})
        else:
            if "secret_code" not in validated_data:
                raise serializers.ValidationError({"secret_code": ["Secret code is needed"]})
            uri = uri % {"secret-code": validated_data.pop("secret_code")}

        uri = uri % {"__version__": "5.0"}

        validated_data["uri"] = uri
        validated_data["datatype"] = public_sources["sources"][source_name]["datatype"]
        validated_data["method"] = "http"
        validated_data["public_source"] = source_name
        return super().create(validated_data)


class PublicSourceViewSet(BaseSourceViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    List all used sources:\n
        curl -k https://x.x.x.x/rest/rules/public_source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":1,"name":"Source1","created_date":"2018-05-04T10:15:46.216023+02:00","updated_date":"2018-05-04T15:22:15.267123+02:00","method":"http","datatype":"sigs","uri":"https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz","cert_verif":true}

    List available public sources:\n
        curl -k https://x.x.x.x/rest/rules/public_source/list_sources/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"oisf/trafficid":{"support_url":"https://redmine.openinfosecfoundation.org/","added":true,"vendor":"OISF","datatype":"sig","license":"MIT","url":"https://raw.githubusercontent.com/jasonish/suricata-trafficid/master/rules/traffic-id.rules","support_url_cleaned":"https://redmine.openinfosecfoundation.org/","min_version":"4.0.0","summary":"Suricata Traffic ID ruleset"},
        ....
        "sslbl/ssl-fp-blacklist":{"added":false,"vendor":"Abuse.ch","license":"Non-Commercial","url":"https://sslbl.abuse.ch/blacklist/sslblacklist.rules","summary":"Abuse.ch SSL Blacklist","datatype":"sig"},
        "et/open":{"added":false,"vendor":"Proofpoint","license":"MIT","url":"https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz","summary":"Emerging Threats Open Ruleset","datatype":"sigs"},
        ....
        "et/pro":{"replaces":["et/open"],"vendor":"Proofpoint","description":"Proofpoint ET Pro is a timely and accurate rule set for detecting and blocking advanced threats","license":"Commercial","subscribe_url":"https://www.proofpoint.com/us/threat-insight/et-pro-ruleset","url":"https://rules.emergingthreatspro.com/%(secret-code)s/suricata-%(__version__)s/etpro.rules.tar.gz","summary":"Emerging Threats Pro Ruleset","subscribe_url_cleaned":"https://www.proofpoint.com/us/threat-insight/et-pro-ruleset","datatype":"sigs","added":false,"parameters":{"secret_code":{"prompt":"Emerging Threats Pro access code"}}}}

    Fetch sources list:\n
        curl -k https://x.x.x.x/rest/rules/public_source/fetch_list_sources/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"fetch":"ok"}

    ==== POST ====\n
    Create public source (you need to call /update_source/ to download the source data and update it):\n
        curl -k https://x.x.x.x/rest/rules/public_source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"name": "sonic public source", "public_source": "oisf/trafficid"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":4,"name":"sonic public source","created_date":"2018-05-07T11:54:56.450782+02:00","updated_date":"2018-05-07T11:54:56.450791+02:00","method":"http","datatype":"sig","uri":"https://raw.githubusercontent.com/jasonish/suricata-trafficid/master/rules/traffic-id.rules","cert_verif":true,"public_source":"oisf/trafficid"}

    Update public source:\n
        curl -k https://x.x.x.x/rest/rules/public_source/<pk-public-source>/update_source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"task_pk": 456}

    Test public source:\n
        curl -k https://x.x.x.x/rest/rules/public_source/<pk-public-source>/test/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"task_pk": 789}

    ==== DELETE ====\n
    Delete public source:\n
        curl -k https://x.x.x.x/rest/rules/public_source/<pk-public-source>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """

    queryset = Source.objects.filter(public_source__isnull=False)
    serializer_class = PublicSourceSerializer
    ordering = ("name",)
    ordering_fields = ("name", "created_date", "updated_date")
    filterset_fields = ("name", "method")
    search_fields = ("name", "method")


class SourceSerializer(BaseSourceSerializer):
    datatype = serializers.CharField(required=True)
    method = serializers.ChoiceField(required=True, choices=Source.FETCH_METHOD)

    class Meta(BaseSourceSerializer.Meta):
        model = BaseSourceSerializer.Meta.model
        fields = (*BaseSourceSerializer.Meta.fields, "method", "uri", "authkey", "comment", "remove_original_sids")
        read_only_fields = BaseSourceSerializer.Meta.read_only_fields

    def validate_datatype(self, value):
        extra_types = get_middleware_module("common").update_source_content_type()
        datatypes = [ct[0] for ct in Source.CONTENT_TYPE + extra_types]
        if value not in datatypes:
            raise serializers.ValidationError("Data type must be one of: {}".format(",".join(datatypes)))
        return value

    def create(self, validated_data):
        validated_data["public_source"] = None
        return super().create(validated_data)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.datatype not in instance.custom_data_type:
            data.pop("remove_original_sids", None)
        return data


class SourceViewSet(BaseSourceViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    List all used sources:\n
        curl -k https://x.x.x.x/rest/rules/source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"pk":1,"name":"Source1","created_date":"2018-05-04T10:15:46.216023+02:00","updated_date":"2018-05-04T15:22:15.267123+02:00","method":"http","datatype":"sigs","uri":"https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz","cert_verif":true,"authkey":"123456789"}

    ==== POST ====\n
    Create custom source:\n
        curl -k https://x.x.x.x/rest/rules/source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"name": "sonic custom source", "method": "local", "datatype": "sigs", "use_sys_proxy": true}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":5,"name":"sonic Custom source","created_date":"2018-05-07T12:01:00.658118+02:00","updated_date":"2018-05-07T12:01:00.658126+02:00","method":"local","datatype":"sigs","uri":null,"cert_verif":true,"authkey":"123456789","use_sys_proxy":true}

    Update custom (only for {method: http}):\n
        curl -k "https://x.x.x.x/rest/rules/source/<pk-source>/update_source/" -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"task_pk":"123"}

    Upload rules (only for {method: local}):\n
        curl -k https://x.x.x.x/rest/rules/source/<pk-source>/upload/ -H 'Authorization: Token <token>' --keepalive-time 20 -F file=@/tmp/emerging.rules.tar.gz  -X POST

    Return:\n
        HTTP/1.1 100 Continue
        HTTP/1.1 200 OK
        {"task_pk": 268}

    Test source:\n
        curl -k https://x.x.x.x/rest/rules/source/<pk-source>/test/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"task_pk": 268}

    Source rule analysis:\n
        curl -k https://x.x.x.x/rest/rules/source/<pk-source>/rules_analysis/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"task_pk": 268}

    Upload edit source:\n
        curl -k https://x.x.x.x/rest/rules/source/<pk-source>/upload/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PUT -d '{"path": "/tmp/trafficid.rules"}'

    Return:\n
        HTTP/1.1 200 OK
        {"task_pk": 268}

    ==== DELETE ====\n
    Delete custom source:\n
        curl -k https://x.x.x.x/rest/rules/source/<pk-source>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X DELETE

    Return:\n
        HTTP/1.1 204 No Content

    =============================================================================================================================================================
    """

    queryset = Source.objects.filter(public_source__isnull=True)
    serializer_class = SourceSerializer
    parser_classes = (MultiPartParser, JSONParser)
    ordering = ("name",)
    ordering_fields = ("name", "created_date", "updated_date", "datatype")
    filterset_fields = ("name", "method", "datatype")
    search_fields = ("name", "method", "datatype")

    @action(detail=True, methods=["post"])
    def upload(self, request, pk):
        return super().upload(request, pk)


class ChangelogSerializer(serializers.ModelSerializer):
    class Meta:
        model = SourceUpdate
        fields = (
            "pk",
            "source",
            "created_date",
            "data",
            "changed",
        )

    def to_representation(self, instance):
        data = super(ChangelogSerializer, self).to_representation(instance)
        data["data"] = instance.diff()
        return data


@extend_schema(tags=["Source"])
class ChangelogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    =============================================================================================================================================================
    Show all Changelogs from all sources:\n
        curl -k https://x.x.x.x/rest/rules/changelog/source/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"count":4,"next":null,"previous":null,"results":[{"pk":1,"source":1,"created_date":"2018-07-03T15:20:59.168931Z","data":{"deleted":[],"date":"2018-07-03T15:20:59.168931Z",
        "updated":[{"msg":"SURICATA TRAFFIC-ID: Debian APT-GET","category":"Suricata Traffic ID ruleset Sigs","sid":300000032,"pk":300000032},
        {"msg":"SURICATA TRAFFIC-ID: Ubuntu APT-GET","category":"Suricata Traffic ID ruleset Sigs","sid":300000033,"pk":300000033}],"added":[],"stats":{"deleted":0,"updated":2,"added":0}},
        "changed":2},{"pk":2,"source":2,"created_date":"2018-07-03T15:25:24.449902Z","data":{"deleted":[],
        "date":"2018-07-03T15:25:24.449902Z","updated":[],"added":[],"stats":{"deleted":0,"updated":0,"added":0}},"changed":0},
        {"pk":3,"source":1,"created_date":"2018-07-03T15:25:25.376499Z","data":{"deleted":[],"date":"2018-07-03T15:25:25.376499Z","updated":[{"msg":"SURICATA TRAFFIC-ID: Debian APT-GET",
        "category":"Suricata Traffic ID ruleset Sigs","sid":300000032,"pk":300000032},{"msg":"SURICATA TRAFFIC-ID: Ubuntu APT-GET","category":"Suricata Traffic ID ruleset Sigs","sid":300000033,
        "pk":300000033}],"added":[],"stats":{"deleted":0,"updated":2,"added":0}},"changed":2},{"pk":4,"source":1,"created_date":"2018-07-03T17:14:02.359963Z",
        "data":{"deleted":[],"date":"2018-07-03T17:14:02.359963Z","updated":[{"msg":"SURICATA TRAFFIC-ID: Debian APT-GET","category":"Suricata Traffic ID ruleset Sigs","sid":300000032,"pk":300000032},
        {"msg":"SURICATA TRAFFIC-ID: Ubuntu APT-GET","category":"Suricata Traffic ID ruleset Sigs","sid":300000033,"pk":300000033}],"added":[],"stats":{"deleted":0,"updated":2,"added":0}}, "changed":2}]}

    Show changelogs filter by source:\n
        curl -k https://x.x.x.x/rest/rules/changelog/source/?source=2 -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    =============================================================================================================================================================
    """

    serializer_class = ChangelogSerializer
    queryset = SourceUpdate.objects.all()
    filterset_fields = ("source",)
    ordering = ("-pk",)
    ordering_fields = ("pk", "source")
    REQUIRED_GROUPS = {
        "READ": ("rules.source_view",),
    }
