import os

from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound
from rest_framework.views import APIView
from rest_framework.routers import DefaultRouter
from rest_framework.response import Response
from suricata.models import Suricata
from django.utils import timezone
from django.conf import settings
from django.urls import re_path
from django.http import HttpResponse


from rules.models import UserAction
from rules.rest_api import CommentSerializer


class SuricataViewSet(APIView):
    """
    =============================================================================================================================================================
    ==== POST ====\n
    Update and Push ruleset:\n
        curl -v -k https://x.x.x.x/rest/suricata/update_push_all/  -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"update_push_all":"ok"}

    =============================================================================================================================================================
    """
    REQUIRED_GROUPS = {
        'WRITE': ('rules.ruleset_update_push',),
    }

    def post(self, request, format=None):
        suri = Suricata.objects.first()
        try:
            suri.ruleset.update()
        except IOError as e:
            raise serializers.ValidationError({'update_push_all': ['Can not fetch data: %s' % e]})
        suri.generate()
        ret = suri.push()
        suri.updated_date = timezone.now()
        suri.save()

        msg = ['Suricata restart already asked']
        if ret:
            msg = 'ok'
            comment = request.data.get('comment', None)
            comment_serializer = CommentSerializer(data={'comment': comment})
            comment_serializer.is_valid(raise_exception=True)

            UserAction.create(
                action_type='update_push_all',
                request=request,
                ruleset=suri.ruleset,
                comment=comment_serializer.validated_data['comment']
            )
        return Response({'update_push_all': msg})


def get_custom_urls():
    urls = [
        re_path(r'suricata/update_push_all/$', SuricataViewSet.as_view(), name='suricata'),
        re_path(r'rules/filestore/(?P<sha256>[0-9a-f]{64})/status/$', FilestoreViewSet.as_view({'get': 'status'}), name='filestore_status'),
        re_path(r'rules/filestore/(?P<sha256>[0-9a-f]{64})/retrieve/$', FilestoreViewSet.as_view({'get': 'retrieve_'}), name='filestore_retrieve'),
        re_path(r'rules/filestore/(?P<sha256>[0-9a-f]{64})/download/$', FilestoreViewSet.as_view({'get': 'download'}), name='filestore_download'),
    ]
    return urls


class FilestoreViewSet(viewsets.ViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Get file status:\n
        curl -k https://x.x.x.x/rest/rules/filestore/e8bbdcfce6e8dcdcbb04c0c7484c701864f8eb3b87ce7ef73352fb5d75146507/status/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json' -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"status":"available"}

    Download file:\n
        curl -O -J -k https://x.x.x.x/rest/rules/filestore/e8bbdcfce6e8dcdcbb04c0c7484c701864f8eb3b87ce7ef73352fb5d75146507/download/ -H 'Authorization: Token <token>' -H 'Content-Type: application/octet-stream' -X GET

    Return:\n
        HTTP/1.1 200 OK
        File Content: e8bbdcfce6e8dcdcbb04c0c7484c701864f8eb3b87ce7ef73352fb5d75146507.data
    """
    REQUIRED_GROUPS = {
        'READ': ('rules.events_view',),
    }

    def _build_src_filestore_path(self, sha256):
        dir_name = sha256[:2]
        path = os.path.join(settings.FILESTORE_SRC, dir_name, sha256)
        return path

    @action(detail=True, methods=['get'])
    def status(self, request, sha256):
        status = 'unknown'

        path = self._build_src_filestore_path(sha256)
        if os.path.isfile(path):
            status = 'available'

        return Response({'status': status})

    @action(detail=True, methods=['get'], url_path='retrieve')
    def retrieve_(self, request, sha256):
        return Response({'retrieve': 'done'})

    @action(detail=True, methods=['get'])
    def download(self, request, sha256):
        path = self._build_src_filestore_path(sha256)
        if not os.path.exists(path):
            raise NotFound(detail='Unknown filename "%s"' % sha256)

        content = None
        with open(path, 'rb') as filestore:
            content = filestore.read()

        response = HttpResponse(content)
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = 'attachment; filename="%s.data"' % sha256
        return response


router = DefaultRouter()
