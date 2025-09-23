"""
Copyright(C) 2014, Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
"""

import json
import tarfile
from io import BytesIO

from django import forms
from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction
from django.db.models import F

from rules.models.filter_sets import FilterSet
from rules.models.model import Ruleset, Threshold, Transformation, RuleProcessingFilter, RuleProcessingFilterDef

from .common import BaseEditForm, CommentForm
from .misc import RulesetPolicyEditPermForm
from .source import RulesetChoiceForm


MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)


class PoliciesForm(RulesetPolicyEditPermForm, BaseEditForm, forms.Form):
    file = forms.FileField(required=True)

    @staticmethod
    def _import(file_, delete):
        from scirius.utils import get_middleware_module

        with tarfile.open(fileobj=file_, mode="r:gz") as tar:
            policy = tar.getmember("policies.json")
            content = json.loads(tar.extractfile(policy).read().decode())

            with transaction.atomic():
                if delete:
                    removed_indexes = list(
                        RuleProcessingFilter.objects.filter(imported=True)
                        .order_by("-index")
                        .values_list("index", flat=True)
                    )
                    RuleProcessingFilter.objects.filter(imported=True).delete()

                    for index in removed_indexes:
                        RuleProcessingFilter.objects.filter(index__gt=index).update(index=F("index") - 1)

                    FilterSet.objects.filter(user_id=None, imported=True).delete()
                    get_middleware_module("common").delete_policies()

                if len(content) > 0:
                    RuleProcessingFilter.objects.update(index=F("index") + len(content))

                for item in content:
                    extra_policies = get_middleware_module("common").extract_policies(item)

                    filter_defs_list = item.pop("filter_defs")
                    rulesets = item.pop("rulesets")

                    item["imported"] = True
                    filter_ = RuleProcessingFilter.objects.create(**item)
                    filter_.rulesets.set(Ruleset.objects.filter(name__in=rulesets))

                    for filter_defs in filter_defs_list:
                        filter_defs["proc_filter"] = filter_
                        filter_defs = RuleProcessingFilterDef.objects.create(**filter_defs)

                    if extra_policies:
                        extra_policies.update({"filter_": filter_})
                        get_middleware_module("common").import_policies(**extra_policies)

                filterset = tar.getmember("filtersets.json")
                content = json.loads(tar.extractfile(filterset).read().decode())

                for item in content:
                    item["imported"] = True
                    FilterSet.objects.get_or_create(**item)

    @staticmethod
    def _export():
        from scirius.utils import get_middleware_module

        filter_fields = [f.name for f in RuleProcessingFilter._meta.get_fields() if f.name not in ("id", "ruleset")]
        filterdef_fields = [
            f.name for f in RuleProcessingFilterDef._meta.get_fields() if f.name not in ("id", "proc_filter")
        ]
        filterset_fields = [f.name for f in FilterSet._meta.get_fields() if f.name not in ("id", "user")]

        res = {}
        for proc_filter in RuleProcessingFilter.objects.values(*filter_fields):
            if proc_filter["index"] not in res:
                proc_filter["filter_defs"] = list(
                    RuleProcessingFilterDef.objects.filter(pk=proc_filter["filter_defs"]).values(*filterdef_fields)
                )
                res[proc_filter["index"]] = proc_filter
                proc_filter["rulesets"] = list(
                    Ruleset.objects.filter(pk=proc_filter["rulesets"]).values_list("name", flat=True)
                )
            else:
                filter_defs = (
                    RuleProcessingFilterDef.objects.filter(pk=proc_filter["filter_defs"])
                    .values(*filterdef_fields)
                    .first()
                )
                res[proc_filter["index"]]["filter_defs"].append(filter_defs)

            get_middleware_module("common").update_policies(proc_filter)

        # Get only shared filtersets
        json_filtersets = json.dumps(list(FilterSet.objects.filter(user_id=None).values(*filterset_fields)))
        json_content = json.dumps(list(res.values()), cls=DjangoJSONEncoder)

        tar_path_io = BytesIO()
        with tarfile.open(fileobj=tar_path_io, mode="w:gz") as tar:
            policy_info = tarfile.TarInfo("policies.json")
            policy_info.size = len(json_content)
            tar.addfile(policy_info, BytesIO(bytes(json_content, "utf-8")))

            filtersets_info = tarfile.TarInfo("filtersets.json")
            filtersets_info.size = len(json_filtersets)
            tar.addfile(filtersets_info, BytesIO(bytes(json_filtersets, "utf-8")))

        return tar_path_io


class AddRuleThresholdForm(forms.ModelForm, RulesetChoiceForm):
    rulesets_label = "Add threshold to the following ruleset(s)"
    threshold_type = forms.CharField(widget=forms.HiddenInput())

    class Meta:
        model = Threshold
        exclude = ["ruleset", "rule", "gid", "descr", "net"]


class AddRuleSuppressForm(forms.ModelForm, RulesetChoiceForm):
    rulesets_label = "Add suppression to the following ruleset(s)"
    threshold_type = forms.CharField(widget=forms.HiddenInput())
    net = forms.CharField(required=True)

    class Meta:
        model = Threshold
        exclude = ["ruleset", "rule", "gid", "descr", "type", "count", "seconds"]

    def clean(self):
        cleaned_data = super().clean()
        if "net" in cleaned_data and "," in cleaned_data["net"]:
            cleaned_data["net"] = ",".join([item.strip() for item in cleaned_data["net"].split(",")])


class EditThresholdForm(forms.ModelForm, CommentForm):
    class Meta:
        model = Threshold
        exclude = ["pk", "rule"]


class RuleTransformForm(RulesetChoiceForm):
    rulesets_label = "Apply transformation(s) to the following ruleset(s)"
    action = forms.ChoiceField()
    lateral = forms.ChoiceField()
    target = forms.ChoiceField()

    def __init__(self, *args, **kwargs):
        rule = kwargs.pop("instance")

        super().__init__(*args, **kwargs)
        choices = rule.get_transformation_choices(key=Transformation.ACTION)
        self.fields["action"].choices = choices
        self.fields["lateral"].choices = rule.get_transformation_choices(key=Transformation.LATERAL)
        self.fields["target"].choices = rule.get_transformation_choices(key=Transformation.TARGET)


class RuleCommentForm(forms.Form):
    comment = forms.CharField(widget=forms.Textarea)
