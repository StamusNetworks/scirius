from django.contrib.auth.models import User
from django.conf import settings
from rest_framework import serializers, viewsets
from rest_framework.routers import DefaultRouter, Route
from rest_framework.pagination import PageNumberPagination

from utils import get_middleware_module
from accounts.rest_api import router as accounts_router

class SciriusSetPagination(PageNumberPagination):
    page_size_query_param = 'page_size'


class SciriusReadOnlyModelViewSet(viewsets.ReadOnlyModelViewSet):
    pagination_class = SciriusSetPagination


class SciriusModelViewSet(viewsets.ModelViewSet):
    pagination_class = SciriusSetPagination

from rules.rest_api import router as rules_router, get_custom_urls

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email')


class UserViewSet(SciriusModelViewSet):
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer


# Routers provide an easy way of automatically determining the URL conf.
class SciriusRouter(DefaultRouter):
    def __init__(self, *args, **kwargs):
        super(SciriusRouter, self).__init__(self, *args, **kwargs)
        self.register('scirius/user', UserViewSet)
        self.registry.extend(rules_router.registry)
        self.registry.extend(accounts_router.registry)
        try:
            self.registry.extend(get_middleware_module('rest_api').router.registry)
        except AttributeError:
            pass

    def get_urls(self):
        urls = super(SciriusRouter, self).get_urls()
        urls += get_custom_urls()

        try:
            urls += get_middleware_module('rest_api').get_custom_urls()
        except AttributeError:
            pass

        return urls


router = SciriusRouter()
