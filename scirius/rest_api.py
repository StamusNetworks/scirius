
from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.routers import DefaultRouter, APIRootView as APIRootViewDJango
from rest_framework.permissions import IsAuthenticated

from .utils import get_middleware_module
from accounts.rest_api import router as accounts_router

from .rest_utils import SciriusModelViewSet
from rules.rest_api import router as rules_router, get_custom_urls


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email')


class UserViewSet(SciriusModelViewSet):
    queryset = User.objects.filter(sciriususer__sciriustokenuser__parent__isnull=True).order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]


class APIRootView(APIRootViewDJango):
    pass


# Routers provide an easy way of automatically determining the URL conf.
class SciriusRouter(DefaultRouter):
    def __init__(self, *args, **kwargs):
        super(SciriusRouter, self).__init__(self, *args, **kwargs)
        self.register('scirius/user', UserViewSet)
        self.registry.extend(rules_router.registry)
        self.registry.extend(accounts_router.registry)
        self.APIRootView = APIRootView
        self.APIRootView.permission_classes = [IsAuthenticated]
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
