from __future__ import unicode_literals
from rest_framework.views import APIView
from rest_framework import serializers
from rest_framework.routers import DefaultRouter, url
from rest_framework.response import Response
from suricata.models import Suricata
from rest_framework.decorators import list_route
from django.utils import timezone

from rules.models import UserAction
from rules.rest_api import CommentSerializer


class SuricataViewSet(APIView):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Update and Push ruleset:\n
        curl -v -k https://x.x.x.x/rest/suricata/update_push_all/  -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST

    Return:\n
        HTTP/1.1 200 OK
        {"update_push_all":"ok"}

    =============================================================================================================================================================
    """

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
                    user=request.user,
                    ruleset=suri.ruleset,
                    comment=comment_serializer.validated_data['comment']
            )
        return Response({'update_push_all': msg})


def get_custom_urls():
    urls = []
    url_ = url(r'suricata/update_push_all/$', SuricataViewSet.as_view(), name='suricata')
    urls.append(url_)
    return urls


router = DefaultRouter()
