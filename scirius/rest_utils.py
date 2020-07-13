
from rest_framework import viewsets
from rest_framework.pagination import PageNumberPagination

class SciriusSetPagination(PageNumberPagination):
    page_size_query_param = 'page_size'


class SciriusReadOnlyModelViewSet(viewsets.ReadOnlyModelViewSet):
    pagination_class = SciriusSetPagination


class SciriusModelViewSet(viewsets.ModelViewSet):
    pagination_class = SciriusSetPagination
