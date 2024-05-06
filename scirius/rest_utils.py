from django.conf import settings

from rest_framework import viewsets
from rest_framework.pagination import PageNumberPagination


class SciriusSetPagination(PageNumberPagination):
    page_size_query_param = 'page_size'


class SciriusReadOnlyModelViewSet(viewsets.ReadOnlyModelViewSet):
    pagination_class = SciriusSetPagination


class SciriusModelViewSet(viewsets.ModelViewSet):
    pagination_class = SciriusSetPagination


class ESManageMultipleESIndexesViewSet:
    INDEXES = {
        'alert': {
            'index': settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX + '*',
            'default': 'true'
        },
        'stamus': {
            'index': settings.ELASTICSEARCH_LOGSTASH_INDEX + 'stamus-*',
            'default': 'false'
        },
        'discovery': {
            'index': settings.ELASTICSEARCH_LOGSTASH_ALERT_INDEX + '*',
            'default': 'false'
        }
    }
