
from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.routers import DefaultRouter, APIRootView as APIRootViewDJango
from rest_framework.permissions import IsAuthenticated

from .utils import get_middleware_module
from accounts.rest_api import router as accounts_router

from rules.rest_api import router as rules_router, get_custom_urls
import contextlib


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email')


class APIRootView(APIRootViewDJango):
    pass


# Routers provide an easy way of automatically determining the URL conf.
class SciriusRouter(DefaultRouter):
    def __init__(self, *args, **kwargs):
        super(SciriusRouter, self).__init__(self, *args, **kwargs)
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


class SciriusRouterV2(DefaultRouter):
    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)
        self.APIRootView = APIRootView
        self.APIRootView.permission_classes = [IsAuthenticated]

        with contextlib.suppress(AttributeError):
            self.registry.extend(get_middleware_module('rest_api').router_v2.registry)


router = SciriusRouter()
router_v2 = SciriusRouterV2()
