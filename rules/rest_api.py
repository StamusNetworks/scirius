from django.conf import settings
from rest_framework import serializers, viewsets, permissions
from rest_framework.routers import DefaultRouter

from rules.models import Ruleset


class ModelSerializer(serializers.ModelSerializer):
    def field_changed(self, field):
        if field not in self._validated_data:
            return False
        if self.instance is None:
            return True
        return getattr(self.instance, field) != self._validated_data[field]

    def get_field_val(self, field, data):
        if field in data:
            return data[field]
        if self.instance is not None:
            return getattr(self.instance, field)
        return None


class RulesetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ruleset
        fields = ('name',)


class RulesetViewSet(viewsets.ModelViewSet):
    queryset = Ruleset.objects.all()
    serializer_class = RulesetSerializer


router = DefaultRouter()
router.register('rules/ruleset', RulesetViewSet)
