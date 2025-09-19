from django.conf import settings
from django_filters import rest_framework as filters
from rest_framework import serializers
from rest_framework.exceptions import APIException

Probe = __import__(settings.RULESET_MIDDLEWARE)


class ServiceUnavailableException(APIException):
    status_code = 500
    default_detail = "Internal Server Error."
    default_code = "internal_error"


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


class CommentSerializer(serializers.Serializer):
    comment = serializers.CharField(required=False, allow_blank=True, write_only=True, allow_null=True)


class ListFilter(filters.CharFilter):
    def sanitize(self, value_list):
        """
        remove empty items in case of ?number=1,,2
        """
        return [v for v in value_list if v != ""]

    def customize(self, value):
        return value

    def filter(self, qs, value):
        multiple_vals = value.split(",")
        multiple_vals = self.sanitize(multiple_vals)
        multiple_vals = list(map(self.customize, multiple_vals))
        for val in multiple_vals:
            qs = super().filter(qs, val)
        return qs
