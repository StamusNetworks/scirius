from django.contrib.auth.models import User
from django.conf import settings
from rest_framework import serializers, viewsets
from rest_framework.routers import DefaultRouter

from utils import get_middleware_module
from rules.rest_api import router as rules_router


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email')


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer


# Routers provide an easy way of automatically determining the URL conf.
class SciriusRouter(DefaultRouter):
    def __init__(self, *args, **kwargs):
        super(SciriusRouter, self).__init__(self, *args, **kwargs)
        self.register('scirius/user', UserViewSet)
        self.registry.extend(rules_router.registry)
        try:
            self.registry.extend(get_middleware_module('rest_api').router.registry)
        except AttributeError:
            pass

router = SciriusRouter()
