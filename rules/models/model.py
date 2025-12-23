"""
Copyright(C) 2014-2018 Stamus Networks
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

import base64
import fcntl
import json
import logging
import os
import re
import shutil
import structlog
import tarfile
import tempfile
from collections import OrderedDict
from copy import deepcopy
from datetime import date as datetime_date
from enum import Enum, unique
from io import BytesIO
from typing import ClassVar, Iterable, TypedDict

import IPy
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import FieldError, SuspiciousOperation, ValidationError
from django.db import models, transaction
from django.db.models import QuerySet
from django.db.models.functions import Coalesce
from django.db.utils import IntegrityError
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html, format_html_join
from idstools import rule as rule_idstools
from ipware.ip import get_client_ip

from rules.ioc_mapping import IOC_MAPPING as IOC_MAP
from rules.models.common import DuplicateSidException
from rules.suripyg import SuriHTMLFormat
from rules.tests_rules import TestRules
from rules.validators import validate_addresses_or_networks

request_logger = logging.getLogger("django.request")
logger = structlog.get_logger("django_structlog")


class UserActionItem(TypedDict):
    title: str
    perm: str
    description: str


class UserAction(models.Model):
    ACTIONS: ClassVar[dict[str, UserActionItem]] = OrderedDict(
        [
            # Login/Logout
            (
                "create_user",
                {
                    "description": "{user} has created new user {new_user}",
                    "title": "Create User",
                    "perm": "rules.configuration_auth",
                },
            ),
            (
                "edit_user",
                {
                    "description": "{user} has edited user {other_user}",
                    "title": "Edit User",
                    "perm": "rules.configuration_auth",
                },
            ),
            (
                "edit_user_token",
                {
                    "description": "{user} has edited {other_user} token",
                    "title": "Edit User Token",
                    "perm": "rules.configuration_auth",
                },
            ),
            (
                "edit_user_password",
                {
                    "description": "{user} has edited {other_user} password",
                    "title": "Edit User Password",
                    "perm": "rules.configuration_auth",
                },
            ),
            (
                "delete_user",
                {
                    "description": "{user} has deleted user {old_user}",
                    "title": "Delete User",
                    "perm": "rules.configuration_auth",
                },
            ),
            (
                "create_group",
                {
                    "description": "{user} has created new role {new_group}",
                    "title": "Create Role",
                    "perm": "rules.configuration_auth",
                },
            ),
            (
                "edit_group",
                {
                    "description": "{user} has edited role {group}",
                    "title": "Edit Role",
                    "perm": "rules.configuration_auth",
                },
            ),
            (
                "delete_group",
                {
                    "description": "{user} has deleted role {group}",
                    "title": "Delete Role",
                    "perm": "rules.configuration_auth",
                },
            ),
            ("login", {"description": "Logged in as {user}", "title": "Login", "perm": "rules.configuration_auth"}),
            ("logout", {"description": "{user} has logged out", "title": "Logout", "perm": "rules.configuration_auth"}),
            # Sources:
            (
                "create_source",
                {
                    "description": "{user} has created source {source}",
                    "title": "Create Source",
                    "perm": "rules.source_view",
                },
            ),
            (
                "update_source",
                {
                    "description": "{user} has updated source {source}",
                    "title": "Update Source",
                    "perm": "rules.source_view",
                },
            ),
            (
                "edit_source",
                {
                    "description": "{user} has edited source {source}",
                    "title": "Edit Source",
                    "perm": "rules.source_view",
                },
            ),
            (
                "upload_source",
                {
                    "description": "{user} has uploaded source {source}",
                    "title": "Upload Source",
                    "perm": "rules.source_view",
                },
            ),
            (
                "enable_source",
                {
                    "description": "{user} has enabled source {source} in ruleset {ruleset}",
                    "title": "Enable Source",
                    "perm": "rules.source_view",
                },
            ),
            (
                "disable_source",
                {
                    "description": "{user} has disabled source {source} in ruleset {ruleset}",
                    "title": "Disable Source",
                    "perm": "rules.source_view",
                },
            ),
            (
                "delete_source",
                {
                    "description": "{user} has deleted source {source}",
                    "title": "Delete Source",
                    "perm": "rules.source_view",
                },
            ),
            # Rulesets:
            (
                "create_ruleset",
                {
                    "description": "{user} has created ruleset {ruleset}",
                    "title": "Create Ruleset",
                    "perm": "rules.source_view",
                },
            ),
            (
                "transform_ruleset",
                {
                    "description": "{user} has transformed ruleset {ruleset} to {transformation}",
                    "title": "Transform Ruleset",
                    "perm": "rules.source_view",
                },
            ),
            (
                "edit_ruleset",
                {
                    "description": "{user} has edited ruleset {ruleset}",
                    "title": "Edit Ruleset",
                    "perm": "rules.source_view",
                },
            ),
            (
                "copy_ruleset",
                {
                    "description": "{user} has copied ruleset {ruleset}",
                    "title": "Copy Ruleset",
                    "perm": "rules.source_view",
                },
            ),
            (
                "delete_ruleset",
                {
                    "description": "{user} has deleted ruleset {ruleset}",
                    "title": "Delete Ruleset",
                    "perm": "rules.source_view",
                },
            ),
            # Categories:
            (
                "enable_category",
                {
                    "description": "{user} has enabled category {category} in ruleset {ruleset}",
                    "title": "Enable Category",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            (
                "transform_category",
                {
                    "description": "{user} has transformed category {category} to {transformation} in ruleset {ruleset}",
                    "title": "Transform Category",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            (
                "disable_category",
                {
                    "description": "{user} has disabled category {category} in ruleset {ruleset}",
                    "title": "Disable Category",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            # Rules:
            (
                "enable_rule",
                {
                    "description": "{user} has enabled rule {rule} in ruleset {ruleset}",
                    "title": "Enable Rule",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            (
                "comment_rule",
                {
                    "description": "{user} has commented rule {rule}",
                    "title": "Comment Rule",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            (
                "transform_rule",
                {
                    "description": "{user} has transformed rule {rule} to {transformation} in ruleset {ruleset}",
                    "title": "Transform Rule",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            (
                "suppress_rule",
                {
                    "description": "{user} has suppressed rule {rule} in ruleset {ruleset}",
                    "title": "Suppress Rule",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            (
                "disable_rule",
                {
                    "description": "{user} has disabled rule {rule} in ruleset {ruleset}",
                    "title": "Disable Rule",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            (
                "delete_suppress_rule",
                {
                    "description": "{user} has deleted suppressed rule {rule} in ruleset {ruleset}",
                    "title": "Delete Suppress Rule",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            # Toggle availability
            (
                "toggle_availability",
                {
                    "description": "{user} has modified rule availability {rule}",
                    "title": "Toggle Availability",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            # Thresholds:
            (
                "create_threshold",
                {
                    "description": "{user} has created threshold on rule {rule} in ruleset {ruleset}",
                    "title": "Create Threshold",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            (
                "edit_threshold",
                {
                    "description": "{user} has edited threshold {threshold} on rule {rule} in ruleset {ruleset}",
                    "title": "Edit Threshold",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            (
                "delete_threshold",
                {
                    "description": "{user} has deleted threshold {threshold} on rule {rule} in ruleset {ruleset}",
                    "title": "Delete Threshold",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            # Used only in REST API
            (
                "delete_transform_ruleset",
                {
                    "description": "{user} has deleted transformation {transformation} on ruleset {ruleset}",
                    "title": "Deleted Ruleset Transformation",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            (
                "delete_transform_rule",
                {
                    "description": "{user} has deleted transformation {transformation} on rule {rule} in ruleset {ruleset}",
                    "title": "Delete Rule Transformation",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            (
                "delete_transform_category",
                {
                    "description": "{user} has deleted transformation {transformation} on category {category} in ruleset {ruleset}",
                    "title": "Delete Category Transformation",
                    "perm": "rules.ruleset_policy_view",
                },
            ),
            # End REST API
            # Suricata
            (
                "edit_suricata",
                {
                    "description": "{user} has edited suricata",
                    "title": "Edit Suricata",
                    "perm": "rules.configuration_view",
                },
            ),
            (
                "create_suricata",
                {
                    "description": "{user} has created suricata",
                    "title": "Create Suricata",
                    "perm": "rules.configuration_view",
                },
            ),
            (
                "update_push_all",
                {
                    "description": "{user} has pushed ruleset {ruleset}",
                    "title": "Update/Push ruleset",
                    "perm": "rules.ruleset_update_push",
                },
            ),
            # Settings
            (
                "system_settings",
                {
                    "description": "{user} has edited system settings",
                    "title": "Edit System Settings",
                    "perm": "rules.configuration_view",
                },
            ),
            (
                "delete_alerts",
                {
                    "description": "{user} has deleted alerts from rule {rule}",
                    "title": "Delete Alerts",
                    "perm": "rules.events_view",
                },
            ),
            # Rule processing filter
            (
                "create_rule_filter",
                {
                    "description": "{user} has created rule filter {rule_filter} in ruleset {ruleset}",
                    "title": "Create rule filter",
                    "perm": "rules.events_view",
                },
            ),
            (
                "edit_rule_filter",
                {
                    "description": "{user} has edited rule filter {rule_filter} in ruleset {ruleset}",
                    "title": "Edit rule filter",
                    "perm": "rules.events_view",
                },
            ),
            (
                "delete_rule_filter",
                {
                    "description": "{user} has deleted rule filter {rule_filter} in ruleset {ruleset}",
                    "title": "Delete rule filter",
                    "perm": "rules.events_view",
                },
            ),
        ]
    )

    action_type = models.CharField(max_length=1000, null=True)
    date = models.DateTimeField("event date", default=timezone.now)
    comment = models.TextField(null=True, blank=True)
    user = models.ForeignKey(User, default=None, on_delete=models.SET_NULL, null=True, blank=True)
    username = models.CharField(max_length=150)
    ua_objects = GenericRelation("UserActionObject", related_query_name="ua_objects")
    # Compatibilty
    description = models.CharField(max_length=1512, null=True)
    client_ip = models.CharField(max_length=64, blank=True, null=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.username and self.user:
            self.username = self.user.username

    def __str__(self):
        return self.generate_description()

    @staticmethod
    def get_allowed_actions_type(request):
        from scirius.utils import get_middleware_module

        actions_dict = get_middleware_module("common").get_user_actions_dict()

        actions = []
        for action_type, val in actions_dict.items():
            perm = val.get("perm", "no_perm")
            if request.user.has_perm(perm):
                actions.append(action_type)
        return actions

    @staticmethod
    def _get_request_info(request):
        user = request.user
        if user.__class__.__name__ == "FakeUser" and settings.DEBUG:
            user = User.objects.first()
        return user, get_client_ip(request)[0]

    @classmethod
    def create(cls, **kwargs):
        if "action_type" not in kwargs:
            raise Exception('Cannot create UserAction without "action_type"')

        if "request" in kwargs:
            user, ip = cls._get_request_info(kwargs["request"])
            kwargs.pop("request")
            kwargs.update({"user": user, "client_ip": ip})

        force_insert = bool("force_insert" in kwargs and kwargs.pop("force_insert"))

        # UserAction
        ua_params = {}
        for param in ("action_type", "comment", "user", "date", "client_ip"):
            if param in kwargs:
                ua_params[param] = kwargs.pop(param)

        ua = cls(**ua_params)
        ua.save(force_insert)

        # UserActionObject
        for action_key, action_value in kwargs.items():
            ua_obj_params = {
                "action_key": action_key,
                "action_value": str(action_value)[:100],
                "user_action": ua,
            }

            if not isinstance(action_value, str):
                ua_obj_params["content"] = action_value

            ua_obj = UserActionObject(**ua_obj_params)
            ua_obj.save()

        # Used as test
        ua.generate_description(ua_params["user"])

        # Warning; do not remove.
        # hack callback is called after UserAction.save is called. So the
        # 2nd save will trigger the callback, once UserActionObject
        # have been created
        ua.save()

    @staticmethod
    def _is_action_authorized(action_key, user):
        if user and action_key in {"ruleset", "source"}:
            return bool(user.has_perm("rules.ruleset_policy_view"))

        return True

    def generate_description(self, user=None):
        if self.description:
            return self.description

        from scirius.utils import get_middleware_module

        actions_dict = get_middleware_module("common").get_user_actions_dict()
        if self.action_type not in list(actions_dict.keys()):
            raise Exception('Unknown action type "%s"' % self.action_type)

        format_ = {"user": format_html("<strong>{}</strong>", self.username), "datetime": self.date}
        actions = UserActionObject.objects.filter(user_action=self).all()

        for action in actions:
            if (
                action.content and hasattr(action.content, "get_absolute_url") and self._is_action_authorized(action.action_key, user)
            ):
                format_[action.action_key] = format_html(
                    '<a href="{}"><strong>{}</strong></a>', action.content.get_absolute_url(), action.action_value
                )
            else:
                format_[action.action_key] = format_html("<strong>{}</strong>", action.action_value)

        try:
            html = format_html(actions_dict[self.action_type]["description"], **format_)
        except KeyError:
            # bug compatibility: workaround for action_value > 100
            # UserActionObjects related to UserAction (self) were
            # not inserted on creation
            html = ""
        return html

    def get_title(self):
        from scirius.utils import get_middleware_module

        actions_dict = get_middleware_module("common").get_user_actions_dict()
        if self.action_type not in list(actions_dict.keys()):
            raise Exception('Unknown action type "%s"' % self.action_type)

        return actions_dict[self.action_type]["title"]

    @staticmethod
    def get_icon():
        return "pficon-user"

    def get_icons(self):
        actions = UserActionObject.objects.filter(user_action=self).all()
        icons = [(self.get_icon(), self.username)]

        for action in actions:
            # ==== Coner cases
            # transformation is str type
            # or workaround for UserAction which can contains no instance but str (ex: create a source without a ruleset)
            if action.action_key in ("transformation", "threat_status", "notebooks") or (
                action.action_key == "ruleset" and action.action_value == "No Ruleset"
            ):
                continue

            ct = action.content_type
            klass = ct.model_class()

            if hasattr(klass, "get_icon"):
                lb = action.action_value

                icon = klass.get_icon()
                instance = klass.objects.filter(pk=action.object_id).first()

                if instance:
                    if isinstance(instance, Source):
                        icon = Source.get_icon(instance)

                    if isinstance(instance, Rule):
                        lb = instance.pk

                    if isinstance(instance, RuleProcessingFilter) and instance.action == "threat":
                        lb = instance.threatmethod.threat.name

                icons.append((icon, lb))

        return format_html_join(
            "\n",
            '<div class="list-view-pf-additional-info-item"><span class="fa {}"></span>{}</div>',
            ((icon, klass_name) for icon, klass_name in icons),
        )

    @staticmethod
    def get_user_actions_dict():
        return deepcopy(UserAction.ACTIONS)


class UserActionObject(models.Model):
    action_key = models.CharField(max_length=20)
    action_value = models.CharField(max_length=100)

    user_action = models.ForeignKey(UserAction, related_name="user_action_objects", on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True)
    object_id = models.PositiveIntegerField(null=True)
    content = GenericForeignKey("content_type", "object_id")


def validate_source_datatype(datatype):
    from scirius.utils import get_middleware_module

    extra_types = get_middleware_module("common").update_source_content_type()
    datatypes = [ct[0] for ct in Source.CONTENT_TYPE + extra_types]
    if datatype not in datatypes:
        if datatype in get_middleware_module("common").custom_source_datatype():
            if Source.objects.filter(datatype="threat").count() > 0:
                raise ValidationError('You cannot add more than 1 "%s" source' % datatype)
        else:
            raise ValidationError(
                'Invalid data type "%s", must be one of %s' % (datatype, ", ".join(sorted(datatypes)))
            )


class InvalidCategoryException(Exception):
    pass


class Source(models.Model):
    FETCH_METHOD = (
        ("http", "HTTP URL"),
        # ('https', 'HTTPS URL'),
        ("local", "Upload"),
    )
    CONTENT_TYPE: ClassVar[list[tuple[str, str]]] = [
        ("sigs", "Signatures files in tar archive"),
        ("sig", "Individual Signatures file"),
        ("ioc", "IoC"),
        # ('iprep', 'IP reputation files'),
        ("other", "Other content"),
        ("b64dataset", "String dataset file"),
    ]
    IOC_TYPE: ClassVar[list[tuple[str, str]]] = [
        ("hostname", "Hostname"),
        ("domain_name", "Domain Name"),
        ("ip", "IP"),
        ("filename", "Filename"),
        ("url", "URL"),
        ("http-user-agent", "HTTP User Agent"),
        ("http-cookie", "HTTP Cookie"),
    ]
    IOC_MAPPING = IOC_MAP

    TMP_DIR = "/tmp/"  # noqa: S108
    REFRESH_LOCK_ID = "source-lock"
    REFRESH_LOCK_EXPIRE = 60 * 10
    DATASET_PATH = "/var/log/suricata/dataset/"

    name = models.CharField(max_length=100, unique=True)
    created_date = models.DateTimeField("date created", auto_now_add=True)
    updated_date = models.DateTimeField("date updated", blank=True, null=True)
    method = models.CharField(max_length=10, choices=FETCH_METHOD)
    datatype = models.CharField(max_length=10)
    # ioc fields
    ioc_type = models.CharField(max_length=20, blank=True, null=True, choices=IOC_TYPE)
    uri = models.CharField(max_length=400, blank=True, null=True)
    cert_verif = models.BooleanField("Check certificates", default=True)
    authkey = models.CharField(max_length=400, blank=True, null=True)
    public_source = models.CharField(max_length=100, blank=True, null=True)
    use_iprep = models.BooleanField("Use IP reputation for group signatures", default=True)
    version = models.IntegerField(default=1)
    use_sys_proxy = models.BooleanField(default=True, verbose_name="Use system proxy")
    untrusted = models.BooleanField(default=True, verbose_name="Source sanitization")
    is_stamus = models.BooleanField(default=False)
    remove_original_sids = models.BooleanField(default=True)

    def __init__(self, *args, **kwargs):
        models.Model.__init__(self, *args, **kwargs)
        if self.method == "http":
            self.update_ruleset = self.update_ruleset_http
        else:
            self.update_ruleset = None
        self.first_run = False
        self.updated_rules = {"added": [], "deleted": [], "updated": []}

        from scirius.utils import get_middleware_module

        self.custom_data_type = get_middleware_module("common").custom_source_datatype()

    def save(self, *args, **kwargs) -> None:
        self.full_clean()

        # creation
        if self._state.adding:
            validate_source_datatype(self.datatype)
        if self.datatype in self.custom_data_type:
            if self.use_iprep:
                self.use_iprep = False
            if self.untrusted:
                self.untrusted = False

        elif self.datatype == "ioc":
            self.untrusted = False
            self.use_iprep = False
            self.remove_original_sids = False
            self.is_stamus = True
        return super().save(*args, **kwargs)

    def clean(self):
        """
        We must check the name when the type is IoC or Other content or String dataset file. The name can only contain
        characters and dash
        """
        if self.datatype in ("ioc", "other", "b64dataset"):
            without_dash = self.name.replace("-", "")
            if not without_dash.isalnum():
                raise ValidationError({"name": ["Source name can only contain alphanum characters and dashes"]})

    def build_ioc_metadata(self):
        items = []
        for item in self.ioc_meta.values("key", "value"):
            items.append(f"{item['key']} {item['value']}")
        return items

    @staticmethod
    def ioc_rules(highlight=False, src_instance=None):
        rules = {}

        if src_instance and src_instance.datatype != "ioc":
            # we cannot edit datatype on source edition page
            return rules

        func = SuriHTMLFormat if highlight else lambda x: x

        rules_info = RuleAtVersion.objects.none()
        if src_instance:
            rules_info = (
                RuleAtVersion.objects.select_related("rule")
                .filter(
                    rule__category__source=src_instance,
                )
                .order_by("rule__sid", "rev")
            )

        for ioc_type, value in Source.IOC_MAPPING.items():
            for idx, rule in enumerate(value["signatures"]):
                if ioc_type not in rules:
                    rules[ioc_type] = []

                found = True
                updated = timezone.now().strftime("%Y_%m_%d")

                rule_data = {
                    "metadata": "{metadata}",
                    "updated_at": updated,
                }

                if src_instance:
                    if ioc_type == src_instance.ioc_type:
                        rule_data.update(
                            {
                                "sid": rules_info[idx].rule.sid,
                                "rev": rules_info[idx].rev + 1,
                                "created_at": rules_info[idx].created.strftime("%Y_%m_%d"),
                            }
                        )
                    else:
                        found = False
                else:
                    rule_data.update({"sid": Rule.get_ioc_next_sid() + idx, "rev": 1, "created_at": updated})

                if found:
                    rules[ioc_type].append(func(rule.format(name="{name}", **rule_data)))
        return rules

    def add_self_in_rulesets(self, rulesets, request):
        for ruleset in rulesets:
            ruleset.sources.add(self)

    def set_is_stamus(self):
        copyright_ = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), "rules", "COPYRIGHT")
        if os.path.exists(copyright_):
            with open(copyright_, "r") as f:
                content = f.read()
            if re.match(r"Copyright \d+ Stamus Networks", content):
                # used in Rule.clean to know if checking sid ranges
                self.is_stamus = True

    def remove_rules_dir(self):
        dir_path = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), "rules")
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)

    def enable(self, ruleset, request=None, comment=None):
        ruleset.sources.add(self)

        for cat in Category.objects.filter(source=self):
            if cat not in ruleset.categories.all():
                ruleset.categories.add(cat)

        ruleset.save()
        if request:
            UserAction.create(
                action_type="enable_source", comment=comment, request=request, source=self, ruleset=ruleset
            )

    def disable(self, ruleset, request=None, comment=None):
        ruleset.sources.remove(self)

        for cat in Category.objects.filter(source=self):
            if cat in ruleset.categories.all():
                ruleset.categories.remove(cat)

        ruleset.save()
        if request:
            UserAction.create(
                action_type="disable_source", comment=comment, request=request, source=self, ruleset=ruleset
            )

    def to_buffer(self):
        categories = Category.objects.filter(source=self)
        ravs = RuleAtVersion.objects.select_related("rule").filter(rule__category__in=categories, version=0)
        file_content = f"# Rules file for {self.name} generated by Scirius at {timezone.now()!s}\n"
        rules_content = [rav.content for rav in ravs]
        file_content += "\n".join(rules_content)
        return file_content

    def test_rule_buffer(self, rule_buffer, engine_analysis=False):
        testor = TestRules()
        related_files, cats_content, iprep_content = self.prepare_tests_files()

        return testor.check_rule_buffer(
            rule_buffer,
            related_files=related_files,
            cats_content=cats_content,
            iprep_content=iprep_content,
            engine_analysis=engine_analysis,
        )

    def prepare_tests_files(self):
        tmpdir = tempfile.mkdtemp()
        cats_content, iprep_content = self.export_files(tmpdir)
        related_files = {}

        for root, _, files in os.walk(tmpdir):
            for f in files:
                fullpath = os.path.join(root, f)
                if os.path.getsize(fullpath) < 50 * 1024:
                    with open(fullpath) as cf:
                        related_files[f] = cf.read()
                else:
                    related_files[f] = ""
                    with open(fullpath) as cf:
                        for idx, line in enumerate(cf.readlines()):
                            if idx >= 1000:
                                break
                            related_files[f] += line

        shutil.rmtree(tmpdir)
        return related_files, cats_content, iprep_content

    def analyse_rules(self):
        testor = TestRules()
        related_files, cats_content, iprep_content = self.prepare_tests_files()

        all_versions = RuleAtVersion.get_versions_to_analyse()
        for version in all_versions:
            contents = (
                RuleAtVersion.objects.filter(
                    rule__category__source=self, updated_date__gte=self.updated_date, version=version
                )
                .distinct()
                .values_list("content", flat=True)
            )

            if contents:
                content = testor.rules_infos(
                    "\n".join(contents) + f'\n## SLS dataset-dir: {Source.DATASET_PATH}\n## SLS suricata-options: --set datasets.limits.single-hashsize=5000000',
                    related_files=related_files,
                    cats_content=cats_content,
                    iprep_content=iprep_content,
                )
                RuleAtVersion.write_analyse(content, version)

    def test(self):
        rule_buffer = self.to_buffer() + "\n## SLS suricata-options: --set datasets.limits.single-hashsize=5000000"
        return self.test_rule_buffer(rule_buffer)

    @classmethod
    def get_sources(cls):
        return cls.objects.annotate(
            cats_count=models.Count("category", distinct=True), rules_count=models.Count("category__rule")
        ).order_by("name")

    @staticmethod
    def get_icon(instance=None):
        if instance and instance.method == "http":
            return "fa fa-external-link list-view-pf-icon-sm"
        return "pficon pficon-volume list-view-pf-icon-sm"

    def delete(self):
        # delete git tree
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        try:
            shutil.rmtree(source_git_dir)
        # Ignore error if not present
        except OSError:
            pass
        # delete model
        models.Model.delete(self)

    def __str__(self):
        return self.name

    def aggregate_update(self, update):
        self.updated_rules["added"] = list(set(self.updated_rules["added"]).union(set(update["added"])))
        self.updated_rules["deleted"] = list(set(self.updated_rules["deleted"]).union(set(update["deleted"])))
        self.updated_rules["updated"] = list(set(self.updated_rules["updated"]).union(set(update["updated"])))

    def get_categories(self):
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        catname = re.compile(r"(.+)\.rules$")
        re_version = re.compile(r"(\w+)-u(\d+)\.rules$")

        existing_rules_hash = {"groups": {}}
        for rav in (
            RuleAtVersion.objects.filter(rule__category__source=self)
            .prefetch_related("rule")
            .prefetch_related("rule__category")
            .prefetch_related("rule__category__source")
        ):
            rule = rav.rule
            if rule.sid not in existing_rules_hash:
                existing_rules_hash[rule.sid] = {}

            existing_rules_hash[rule.sid][rav.version] = rav

            if self.use_iprep and rule.group:
                if rule.category.name not in existing_rules_hash["groups"]:
                    existing_rules_hash["groups"][rule.category.name] = []
                existing_rules_hash["groups"][rule.category.name].append(rav)

        versions = []
        for f in os.listdir(os.path.join(source_git_dir, "rules")):
            if f.endswith(".rules"):
                match = catname.search(f)
                version_match = re_version.search(f)
                name = match.groups()[0] if not version_match else version_match.group(1)
                version = int(version_match.group(2)) if version_match else 0
                if version > 0:
                    versions.append(version)

                category = Category.objects.filter(source=self, name=name).first()
                if category is None:
                    category = Category.objects.create(
                        source=self,
                        name=name,
                        created_date=timezone.now(),
                        filename=os.path.join("rules", f"{name}.rules"),
                    )
                    for ruleset in self.ruleset_set.all():
                        if ruleset.activate_categories:
                            ruleset.categories.add(category)
                            if name == "stamus":
                                # disable transformation for custom sources (stamus)
                                category.toggle_transformation(ruleset, Transformation.TARGET, Transformation.T_NONE)
                                category.toggle_transformation(ruleset, Transformation.LATERAL, Transformation.L_NO)
                category.get_rules(
                    self, version=version, filename=os.path.join("rules", f), existing_rules_hash=existing_rules_hash
                )
                # get rules in this category
        for category in Category.objects.filter(source=self):
            filenames = [category.filename]
            for version in versions:
                filenames.append(category.filename.replace(".rules", "-u%i.rules" % version))

            delete = True
            for filename in filenames:
                if os.path.isfile(os.path.join(source_git_dir, filename)):
                    delete = False
                    break
            if delete:
                category.delete()

        existing_rules_hash.clear()

    def _check_category_ids(self, f, filename, field_no):
        # Check the file object in argument does not contain category ids < 20
        for line_no, line in enumerate(f.readlines()):
            try:
                line = line.strip()

                if not line or line.startswith(b"#"):
                    continue
                fields = line.split(b",")

                cat_no = int(fields[field_no])
                if cat_no < 20:
                    raise InvalidCategoryException(
                        "Invalid category %i in %s (line %i): category < 20 are reserved to Scirius"
                        % (cat_no, filename, line_no + 1)
                    )
            except (IndexError, ValueError):
                raise Exception("Invalid syntax in file %s (line %i)" % (filename, line_no + 1))

    # Rewrite of https://github.com/python/cpython/blob/master/Lib/tarfile.py
    # Extract tar file but force setting permissions
    @staticmethod
    def _tar_extractall(tarfile, path=".", members=None, *, numeric_owner=False):
        if members is None:
            members = tarfile

        for tarinfo in members:
            tarfile.extract(tarinfo, path, set_attrs=False)
            fpath = os.path.join(path, tarinfo.name)

            if tarinfo.isdir():
                os.chmod(fpath, 0o755)  # noqa: S103
            else:
                os.chmod(fpath, 0o644)

    def handle_rules_in_tar(self, f):
        f.seek(0)
        if not tarfile.is_tarfile(f.name):
            raise OSError("Invalid tar file")

        self.updated_date = timezone.now()
        self.first_run = False

        f.seek(0)
        # extract file
        tfile = tarfile.open(fileobj=f)
        dir_list = []
        rules_dir = None

        for member in tfile.getmembers():
            # only file and dir are allowed
            if not (member.isfile() or member.isdir()):
                raise SuspiciousOperation("Suspect tar file contains non regular file '%s'" % (member.name))

            if member.name.startswith("/") or ".." in member.name:
                raise SuspiciousOperation("Suspect tar file contains invalid path '%s'" % (member.name))

            if member.isdir() and ("/" + member.name).endswith("/rules"):
                if rules_dir:
                    raise SuspiciousOperation("Tar file contains two 'rules' directory instead of one")
                dir_list.append(member)
                rules_dir = member.name

            if member.isfile():
                # we now allow "rules" files even if they are at root directory
                member.name = os.path.join("rules", os.path.basename(member.name))
                dir_list.append(member)

                if member.name.endswith("categories.txt"):
                    f = tfile.extractfile(member.name)
                    self._check_category_ids(f, member.name, 0)

                if member.name.endswith(".list"):
                    f = tfile.extractfile(member.name)
                    self._check_category_ids(f, member.name, 1)

        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        self._tar_extractall(tfile, path=source_git_dir, members=dir_list)
        self.set_is_stamus()

        self.save()
        # Get categories
        self.get_categories()

    def handle_other_file(self, f, b64encode=False):
        self.updated_date = timezone.now()
        self.first_run = False
        rules_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), "rules")

        # create rules dir if needed
        if not os.path.isdir(rules_dir):
            os.makedirs(rules_dir)

        f.seek(0)
        if b64encode is False:
            # copy file content to target
            os.fsync(f)
            shutil.copy(f.name, os.path.join(rules_dir, self.name))
        else:
            target_file = os.path.join(rules_dir, self.name)
            with open(target_file, "wb") as tf:
                tf.writelines(base64.b64encode(stringelt.rstrip(b"\r\n")) + b"\n" for stringelt in f)

        self.save()

    def handle_b64dataset(self, f):
        return self.handle_other_file(f, b64encode=True)

    def handle_ioc_file(self, f_dataset):
        f_dataset.seek(0)

        validator = Source.IOC_MAPPING[self.ioc_type]["validator"]
        if validator:
            for line in f_dataset:
                validator(line.decode().strip())

        if Source.IOC_MAPPING[self.ioc_type]["encoding"] == "b64":
            self.handle_b64dataset(f_dataset)
        else:
            self.handle_other_file(f_dataset)

        self._update_ioc_rules()

    def _update_ioc_rules(self):
        # to know if source is edited or added
        added_source = not self.category_set.exists()
        rules_info = RuleAtVersion.objects.none()
        if not added_source:
            # there is only 1 rav for 1 rule
            rules_info = (
                RuleAtVersion.objects.select_related("rule")
                .filter(rule__category__source=self)
                .order_by("rule__sid", "rev", "rule__created")
            )

        with tempfile.NamedTemporaryFile(dir=self.TMP_DIR, mode="w") as f_rules:
            for idx, rule in enumerate(self.IOC_MAPPING[self.ioc_type]["signatures"]):
                updated = timezone.now().strftime("%Y_%m_%d")
                metadata = "" if not self.ioc_meta.exists() else f", {', '.join(self.build_ioc_metadata())}"

                if added_source:
                    sid = Rule.get_ioc_next_sid() + idx
                    rev = 1
                    created = timezone.now().strftime("%Y_%m_%d")
                else:
                    sid = rules_info[idx].rule.sid
                    rev = rules_info[idx].rev + 1
                    created = rules_info[idx].rule.created.strftime("%Y_%m_%d")

                f_rules.write(
                    rule.format(
                        name=self.name, metadata=metadata, sid=sid, rev=rev, created_at=created, updated_at=updated
                    )
                )
                f_rules.write("\n")
            self.handle_rules_file(f_rules)

    def handle_rules_file(self, f):
        f.seek(0)
        if tarfile.is_tarfile(f.name):
            raise OSError("This is a tar file and not a individual signature file, please select another category")
        f.seek(0)

        self.updated_date = timezone.now()
        self.first_run = False
        rules_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), "rules")

        # create rules dir if needed
        if not os.path.isdir(rules_dir):
            os.makedirs(rules_dir)

        # copy file content to target
        f.seek(0)
        os.fsync(f)
        shutil.copy(f.name, os.path.join(rules_dir, "sigs.rules"))

        self.save()

        # category based on filename
        category = Category.objects.filter(source=self, name=(f"{self.name} Sigs")[:100]).first()
        if category is None:
            category = Category.objects.create(
                source=self,
                name=(f"{self.name} Sigs")[:100],
                created_date=timezone.now(),
                filename=os.path.join("rules", "sigs.rules"),
            )
            for ruleset in self.ruleset_set.all():
                if ruleset.activate_categories:
                    ruleset.categories.add(category)

        category.get_rules(self)
        if Rule.objects.filter(category=category).count() == 0:
            category.delete()
            raise ValidationError("The source %s contains no valid signature" % self.name)

    def handle_custom_file(self, f, upload=False):
        from scirius.utils import get_middleware_module

        f.seek(0)
        if not tarfile.is_tarfile(f.name):
            raise OSError("Invalid tar file")

        self.first_run = False
        self.updated_date = timezone.now()
        sources_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        version_path = os.path.join(sources_dir, "rules", "version.txt")

        # create rules dir if needed
        if not os.path.isdir(sources_dir):
            os.makedirs(sources_dir)

        f.seek(0)
        get_middleware_module("common").extract_custom_source(f, sources_dir)
        self.set_is_stamus()
        if upload:
            sources_path = os.path.join(sources_dir, "rules")
            get_middleware_module("common").update_custom_source(sources_path)

        with open(version_path, "r") as f:
            self.version = int(f.read())

        self.save()
        from scirius.utils import get_middleware_module

        Rule.SID_RANGES = get_middleware_module("common").get_stamus_range(self)
        self.get_categories()

    def json_rules_list(self, rlist):
        rules = []
        for rule in rlist:
            rules.append({"sid": rule.sid, "msg": rule.msg, "category": rule.category.name, "pk": rule.pk})
        # for each rule we create a json object sid + msg + content
        return rules

    def create_update(self):
        # for each set
        update = {}
        update["deleted"] = self.json_rules_list(self.updated_rules["deleted"])
        update["added"] = self.json_rules_list(self.updated_rules["added"])
        update["updated"] = self.json_rules_list(self.updated_rules["updated"])
        SourceUpdate.objects.create(
            source=self,
            created_date=timezone.now(),
            data=json.dumps(update),
            changed=len(update["deleted"]) + len(update["added"]) + len(update["updated"]),
        )

    # This method cannot be called twice consecutively
    @transaction.atomic
    def update(self):
        # lock
        if not os.path.exists(settings.FLOCK_PATH):
            os.makedirs(settings.FLOCK_PATH)
        source_lock_path = os.path.join(settings.FLOCK_PATH, "source_%s" % self.pk)
        source_lock = open(source_lock_path, "w")
        fcntl.flock(source_lock, fcntl.LOCK_EX)

        try:
            # look for categories list: if none, first import
            categories = Category.objects.filter(source=self)
            firstimport = False
            if not categories:
                firstimport = True

            if self.method not in ["http", "local"]:
                raise FieldError("Currently unsupported method")

            need_update = False
            if self.update_ruleset:
                f = tempfile.NamedTemporaryFile(dir=self.TMP_DIR)
                need_update = self.update_ruleset(f)

                if need_update:
                    self._handle_file(f)

            if need_update:
                if (self.datatype in ("sig", "sigs") or self.datatype in self.custom_data_type) and not firstimport:
                    self.create_update()

                if self.datatype in self.custom_data_type:
                    from scirius.utils import get_middleware_module

                    source_path = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), "rules")
                    get_middleware_module("common").update_custom_source(source_path)

                rules_pk = [rule.sid for rule in self.updated_rules["deleted"]]
                Rule.objects.filter(pk__in=rules_pk).delete()

        finally:
            source_lock.close()

    def export_files(self, directory):
        source_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), "rules")
        cats_content = ""
        iprep_content = ""

        datatypes = ["sig", "sigs", "ioc"]
        if self.custom_data_type:
            datatypes.append(self.custom_data_type[0])

        # race condition if a ruleset1 with a sourceA has finished update on SourceA
        # then ruleset2 with sourceA is starting an update
        # => rule analysis is run on this source which has been deleted
        # by sourceA update from ruleset2
        if not os.path.exists(settings.FLOCK_PATH):
            os.makedirs(settings.FLOCK_PATH)
        source_lock_path = os.path.join(settings.FLOCK_PATH, "source_analysis_%s" % self.pk)
        source_lock = open(source_lock_path, "w")
        fcntl.flock(source_lock, fcntl.LOCK_EX)

        try:
            for filename in os.listdir(source_dir):
                full_path = os.path.join(source_dir, filename)

                # don't copy original rules file to dest
                if filename.endswith(".rules") and self.datatype in datatypes:
                    continue

                if filename.endswith("categories.txt") and self.datatype in ("sig", "sigs"):
                    with open(full_path, "r") as f:
                        cats_content = f.read()
                    continue

                if filename.endswith(".list") and self.datatype in ("sig", "sigs"):
                    with open(full_path, "r") as f:
                        iprep_content = f.read()
                    continue

                if os.path.isfile(full_path):
                    shutil.copy2(full_path, directory)
        finally:
            source_lock.close()

        return cats_content, iprep_content

    def get_absolute_url(self):
        return reverse("source", args=[str(self.id)])

    def is_ti_url(self):
        return self.uri.startswith("https://ti.stamus-networks.io/")

    def is_ti_dev_url(self):
        return self.uri.startswith("https://ti-dev.stamus-networks.io/")

    def is_etpro_url(self):
        return (
            self.uri.startswith("https://rules.emergingthreatspro.com/") or self.uri.startswith("https://rules.emergingthreats.net/") or self.is_ti_url()
        )

    def update_ruleset_http(self, f):
        from scirius.utils import RequestsWrapper, get_middleware_module

        get_middleware_module("common").update_custom_sources_url(self)

        agent = f"scirius/{settings.SCIRIUS_VERSION}"
        if os.getenv("STAMUSCTL_SEED"):
            seed = os.getenv("STAMUSCTL_SEED").strip('"')
            agent = f"scirius/{settings.SCIRIUS_VERSION} ({seed})"
        hdrs = {"User-Agent": agent}
        if self.authkey:
            hdrs["Authorization"] = self.authkey

        version_uri = None
        if self.is_etpro_url() or (
            self.datatype not in ("sigs", "sig", "other", "b64dataset", "ioc") and not self.is_ti_dev_url()
        ):
            version_uri = os.path.join(os.path.dirname(self.uri), "version.txt")

        version_server = 1
        if version_uri:
            resp = RequestsWrapper(verify=self.cert_verif, use_proxy=self.use_sys_proxy).get(
                url=version_uri, headers=hdrs
            )
            version_server = int(resp.content.strip())

            if self.version < version_server:
                version_uri = None

        if version_uri is None:
            resp = RequestsWrapper(verify=self.cert_verif, use_proxy=self.use_sys_proxy).get(url=self.uri, headers=hdrs)
            f.write(resp.content)

            self.version = max(self.version, version_server)

            return True

        return False

    def _handle_file(self, _file, upload=False):
        # race condition if a ruleset1 with a sourceA has finished update on SourceA
        # then ruleset2 with sourceA is starting an update
        # => rule analysis is run on this source which has been deleted
        # by sourceA update from ruleset2
        if not os.path.exists(settings.FLOCK_PATH):
            os.makedirs(settings.FLOCK_PATH)
        source_lock_path = os.path.join(settings.FLOCK_PATH, "source_analysis_%s" % self.pk)
        source_lock = open(source_lock_path, "w")
        fcntl.flock(source_lock, fcntl.LOCK_EX)

        try:
            self.remove_rules_dir()

            if self.datatype == "sigs":
                self.handle_rules_in_tar(_file)
            elif self.datatype == "sig":
                self.handle_rules_file(_file)
            elif self.datatype == "other":
                self.handle_other_file(_file)
            elif self.datatype == "b64dataset":
                self.handle_b64dataset(_file)
            elif self.datatype == "ioc":
                self.handle_ioc_file(_file)
            elif self.datatype in self.custom_data_type:
                self.handle_custom_file(_file, upload=upload)
        except DuplicateSidException as e:
            sid = str(e)
            source_name = ""
            if len(sid):
                sub_string = " with other "
                if e.same_source is False:
                    source_name = (
                        f" ({Rule.objects.filter(sid=sid).values_list('category__source__name', flat=True).first()})"
                    )
                else:
                    source_name = self.name
                    sub_string = " in same "
                sid = f"({sid})"
                raise ValidationError(f"The source contains conflicting SID {sid} {sub_string} source {source_name}")
            raise ValidationError("Duplicate sids")
        finally:
            source_lock.close()

    def handle_uploaded_file(self, f):
        from scirius.utils import read_in_chunks

        with tempfile.NamedTemporaryFile(dir=self.TMP_DIR) as dest:
            if hasattr(f, "chunks"):
                # FileField
                for chunk in f.chunks():
                    dest.write(chunk)
            else:
                # python file, from tasks
                for chunk in read_in_chunks(f):
                    dest.write(chunk)

            dest.seek(0)
            self._handle_file(dest, upload=True)

    def new_uploaded_file(self, f):
        firstimport = False
        if Category.objects.filter(source=self).count() == 0:
            firstimport = True

        self.handle_uploaded_file(f)
        if self.datatype in ("sig", "sigs") and not firstimport:
            self.create_update()
        for rule in self.updated_rules["deleted"]:
            rule.delete()


class IoCMeta(models.Model):
    key = models.CharField(max_length=100, null=False, blank=False)
    value = models.CharField(max_length=100, null=False, blank=False)
    ioc_source = models.ForeignKey(Source, on_delete=models.CASCADE, related_name="ioc_meta", null=True, blank=True)


class SourceUpdate(models.Model):
    source = models.ForeignKey(Source, on_delete=models.CASCADE)
    created_date = models.DateTimeField("date of update", blank=True, default=timezone.now)
    # Store update info as a JSON document
    data = models.TextField()
    changed = models.IntegerField(default=0)

    def get_absolute_url(self) -> str:
        return reverse("sourceupdate", args=[str(self.id)])

    def diff(self):
        data = json.loads(self.data)
        diff = data
        diff["stats"] = {"updated": len(data["updated"]), "added": len(data["added"]), "deleted": len(data["deleted"])}
        diff["date"] = self.created_date
        return diff


class TransfoType(Enum):
    @classmethod
    def get_choices(cls, attr_=None):
        return [(attr.value, attr.name.replace("_", " ").title()) for attr in cls if attr_ is None or attr_ == attr]

    @classmethod
    def get_choices_name(cls, attr_=None):
        return [attr.name.replace("_", " ").title() for attr in cls if attr_ is None or attr_ == attr]

    @classmethod
    def get_choices_value(cls, attr_=None):
        return [attr.value for attr in cls if attr_ is None or attr_ == attr]


class Transformation(models.Model):
    @unique
    class Type(TransfoType):
        ACTION = "action"
        LATERAL = "lateral"
        TARGET = "target"
        # cannot be removed: used by 0056_auto_20180223_0823.py
        SUPPRESSED = "suppressed"

    @unique
    class ActionTransfoType(TransfoType):
        DROP = "drop"
        REJECT = "reject"
        FILESTORE = "filestore"
        NONE = "none"
        BYPASS = "bypass"
        CATEGORY_DEFAULT = "category"
        RULESET_DEFAULT = "ruleset"

    @unique
    class LateralTransfoType(TransfoType):
        AUTO = "auto"
        YES = "yes"
        NO = "no"
        CATEGORY_DEFAULT = "category"
        RULESET_DEFAULT = "ruleset"

    @unique
    class TargetTransfoType(TransfoType):
        SOURCE = "src"
        DESTINATION = "dst"
        AUTO = "auto"
        NONE = "none"
        CATEGORY_DEFAULT = "category"
        RULESET_DEFAULT = "ruleset"

    # cannot be removed: used by 0056_auto_20180223_0823.py
    @unique
    class SuppressTransforType(TransfoType):
        SUPPRESSED = "suppressed"

    class Meta:
        abstract = True

    # Keys
    ACTION = Type.ACTION
    LATERAL = Type.LATERAL
    TARGET = Type.TARGET
    # cannot be removed: used by 0056_auto_20180223_0823.py
    SUPPRESSED = Type.SUPPRESSED

    # cannot be removed: used by 0056_auto_20180223_0823.py
    S_SUPPRESSED = SuppressTransforType.SUPPRESSED

    # Action values
    A_DROP = ActionTransfoType.DROP
    A_REJECT = ActionTransfoType.REJECT
    A_FILESTORE = ActionTransfoType.FILESTORE
    A_NONE = ActionTransfoType.NONE
    A_BYPASS = ActionTransfoType.BYPASS
    A_CAT_DEFAULT = ActionTransfoType.CATEGORY_DEFAULT
    A_RULESET_DEFAULT = ActionTransfoType.RULESET_DEFAULT

    # Lateral values
    L_AUTO = LateralTransfoType.AUTO
    L_YES = LateralTransfoType.YES
    L_NO = LateralTransfoType.NO
    L_CAT_DEFAULT = LateralTransfoType.CATEGORY_DEFAULT
    L_RULESET_DEFAULT = LateralTransfoType.RULESET_DEFAULT

    # Target transformations
    T_SOURCE = TargetTransfoType.SOURCE
    T_DESTINATION = TargetTransfoType.DESTINATION
    T_AUTO = TargetTransfoType.AUTO
    T_NONE = TargetTransfoType.NONE
    T_CAT_DEFAULT = TargetTransfoType.CATEGORY_DEFAULT
    T_RULESET_DEFAULT = TargetTransfoType.RULESET_DEFAULT

    AVAILABLE_MODEL_TRANSFO = {
        ACTION.value: (
            A_DROP.value,
            A_REJECT.value,
            A_FILESTORE.value,
            A_BYPASS.value,
            A_NONE.value,
        ),
        LATERAL.value: (
            L_AUTO.value,
            L_YES.value,
            L_NO.value,
        ),
        TARGET.value: (
            T_SOURCE.value,
            T_DESTINATION.value,
            T_AUTO.value,
            T_NONE.value,
        ),
    }

    # Fields
    key = models.CharField(max_length=15, choices=Type.get_choices(), default=Type.ACTION.value)
    value = models.CharField(max_length=15, default=ActionTransfoType.NONE.value)


class Transformable:
    _TARGET_REGEX = re.compile(r' target:\w*;')
    _SET_TARGET_REGEX = re.compile(r"\)$")

    def get_transformation(self, ruleset, key):
        raise NotImplementedError

    def is_transformed(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        raise NotImplementedError

    def _set_target(self, rule, target="dest_ip"):
        target = f' target:{target};)'
        rule.raw = self._SET_TARGET_REGEX.sub(target, rule.raw) if target not in rule.raw else rule.raw

    def _test_scan_rules(self, rule_ids):
        for option in rule_ids.options:
            if option["name"] == "flags":
                if option["value"] == "S,12":
                    return True
                return False
        return False

    def _apply_target_trans(self, rule_ids):
        terms = re.split(r" +", rule_ids.format())
        src = terms[2]
        dst = terms[5]

        if self._test_scan_rules(rule_ids):
            self._set_target(rule_ids, target="dest_ip")
        # external net always seen as bad guy on attack if not OUTBOUND
        elif src == "$EXTERNAL_NET":
            self._set_target(rule_ids, target="dest_ip")

        # external net always seen as bad guy on attack
        elif dst == "$EXTERNAL_NET":
            self._set_target(rule_ids, target="src_ip")

        # any or IP address list on one side and a variable on other side implies variable is our asset so target
        elif (src == "any" or src.startswith("[")) and dst.startswith("$"):
            self._set_target(rule_ids, target="dest_ip")

        # any or IP address list on one side and a variable on other side implies variable is our asset so target
        elif src.startswith("$") and (dst == "any" or dst.startswith("[")):
            self._set_target(rule_ids, target="src_ip")

        elif rule_ids.sid in [2017060, 2023070, 2023071, 2023549, 2024297, 2023548, 2024435, 2023149]:
            self._set_target(rule_ids, target="dest_ip")

        elif rule_ids.sid in []:
            self._set_target(rule_ids, target="src_ip")

    def apply_lateral_target_transfo(self, content, key=Transformation.LATERAL, value=Transformation.L_YES):
        try:
            rule_ids = rule_idstools.parse(content)
        except Exception:
            return content

        # Workaround: ref #674
        # Cannot transform, idstools cannot parse it
        if rule_ids is None:
            return content

        # don't work on commented rules
        if rule_ids.format().startswith("#"):
            return content

        # LATERAL + YES
        if key == Transformation.LATERAL:
            if value == Transformation.L_YES:
                rule_ids.raw = rule_ids.raw.replace("$EXTERNAL_NET", "any")
                return rule_ids.format()
            if value == Transformation.L_AUTO:
                if rule_ids.msg.startswith("ET POLICY"):
                    return content
                for meta in rule_ids.metadata:
                    # if deployment can be internal then we can relax the constraint
                    # on EXTERNAL_NET to try to catch the lateral movement
                    if meta == "deployment Internal" or meta == "deployment Datacenter":
                        rule_ids.raw = rule_ids.raw.replace("$EXTERNAL_NET", "any")

        # TARGET + DST/SRC
        if key == Transformation.TARGET:
            if value == Transformation.T_SOURCE:
                rule_ids.raw = self._TARGET_REGEX.sub('', rule_ids.raw)
                self._set_target(rule_ids, target='src_ip')
            elif value == Transformation.T_DESTINATION:
                rule_ids.raw = self._TARGET_REGEX.sub('', rule_ids.raw)
                self._set_target(rule_ids, target='dest_ip')
            elif value == Transformation.T_NONE:
                rule_ids.raw = self._TARGET_REGEX.sub('', rule_ids.raw)
            elif value == Transformation.T_AUTO:
                target_client = False
                for meta in rule_ids.metadata:
                    if meta.startswith("attack_target"):
                        target_client = True
                        break
                    if meta.startswith("mitre_tactic_id"):
                        target_client = True
                        break
                    if meta.startswith("affected_product"):
                        target_client = True
                        break

                # not satisfactory but doing the best we can not too miss something like
                # a successful bruteforce
                if rule_ids.classtype == "attempted-recon":
                    target_client = True
                if rule_ids.classtype == "not-suspicious":
                    target_client = False
                if target_client is True and "target" not in rule_ids:
                    self._apply_target_trans(rule_ids)

        return rule_ids.format()


class Cache:
    TRANSFORMATIONS = {}

    def __init__(self):
        pass

    @classmethod
    def enable_cache(cls):
        if cls.TRANSFORMATIONS == {}:
            # Actions
            ACTION = Transformation.ACTION
            A_NONE = Transformation.A_NONE
            A_FILESTORE = Transformation.A_FILESTORE
            A_DROP = Transformation.A_DROP
            A_REJECT = Transformation.A_REJECT
            A_BYPASS = Transformation.A_BYPASS

            # Lateral
            LATERAL = Transformation.LATERAL
            L_AUTO = Transformation.L_AUTO
            L_YES = Transformation.L_YES
            L_NO = Transformation.L_NO

            # Target
            TARGET = Transformation.TARGET
            T_AUTO = Transformation.T_AUTO
            T_SOURCE = Transformation.T_SOURCE
            T_DST = Transformation.T_DESTINATION
            T_NONE = Transformation.T_NONE

            rule_str = Rule.__name__.lower()
            category_str = Category.__name__.lower()
            ruleset_str = Ruleset.__name__.lower()

            cls.TRANSFORMATIONS = {
                ACTION: {
                    rule_str: {
                        A_DROP: None,
                        A_REJECT: None,
                        A_FILESTORE: None,
                        A_NONE: None,
                        A_BYPASS: None,
                    },
                    category_str: {
                        A_DROP: None,
                        A_REJECT: None,
                        A_FILESTORE: None,
                        A_NONE: None,
                        A_BYPASS: None,
                    },
                    ruleset_str: {
                        A_DROP: None,
                        A_REJECT: None,
                        A_FILESTORE: None,
                        A_BYPASS: None,
                    },
                },
                LATERAL: {
                    rule_str: {
                        L_AUTO: None,
                        L_YES: None,
                        L_NO: None,
                    },
                    category_str: {
                        L_AUTO: None,
                        L_YES: None,
                        L_NO: None,
                    },
                    ruleset_str: {
                        L_AUTO: None,
                        L_YES: None,
                    },
                },
                TARGET: {
                    rule_str: {
                        T_AUTO: None,
                        T_SOURCE: None,
                        T_DST: None,
                        T_NONE: None,
                    },
                    category_str: {
                        T_AUTO: None,
                        T_SOURCE: None,
                        T_DST: None,
                        T_NONE: None,
                    },
                    ruleset_str: {
                        T_AUTO: None,
                        T_SOURCE: None,
                        T_DST: None,
                    },
                },
            }

            # ##### Rules
            # Actions
            drop_rules = Rule.objects.filter(
                ruletransformation__key=ACTION.value, ruletransformation__value=A_DROP.value
            ).values_list("pk", flat=True)

            reject_rules = Rule.objects.filter(
                ruletransformation__key=ACTION.value, ruletransformation__value=A_REJECT.value
            ).values_list("pk", flat=True)

            filestore_rules = Rule.objects.filter(
                ruletransformation__key=ACTION.value, ruletransformation__value=A_FILESTORE.value
            ).values_list("pk", flat=True)

            none_rules = Rule.objects.filter(
                ruletransformation__key=ACTION.value, ruletransformation__value=A_NONE.value
            ).values_list("pk", flat=True)

            bypass_rules = Rule.objects.filter(
                ruletransformation__key=ACTION.value, ruletransformation__value=A_BYPASS.value
            ).values_list("pk", flat=True)

            # Lateral
            rule_l_auto = Rule.objects.filter(
                ruletransformation__key=LATERAL.value, ruletransformation__value=L_AUTO.value
            ).values_list("pk", flat=True)

            rule_l_yes = Rule.objects.filter(
                ruletransformation__key=LATERAL.value, ruletransformation__value=L_YES.value
            ).values_list("pk", flat=True)

            rule_l_no = Rule.objects.filter(
                ruletransformation__key=LATERAL.value, ruletransformation__value=L_NO.value
            ).values_list("pk", flat=True)

            # Target
            rule_t_auto = Rule.objects.filter(
                ruletransformation__key=TARGET.value, ruletransformation__value=T_AUTO.value
            ).values_list("pk", flat=True)

            rule_t_src = Rule.objects.filter(
                ruletransformation__key=TARGET.value, ruletransformation__value=T_SOURCE.value
            ).values_list("pk", flat=True)

            rule_t_dst = Rule.objects.filter(
                ruletransformation__key=TARGET.value, ruletransformation__value=T_DST.value
            ).values_list("pk", flat=True)

            rule_t_none = Rule.objects.filter(
                ruletransformation__key=TARGET.value, ruletransformation__value=T_NONE.value
            ).values_list("pk", flat=True)

            # #### Categories
            # Actions
            drop_cats = Category.objects.filter(
                categorytransformation__key=ACTION.value, categorytransformation__value=A_DROP.value
            ).values_list("pk", flat=True)

            reject_cats = Category.objects.filter(
                categorytransformation__key=ACTION.value, categorytransformation__value=A_REJECT.value
            ).values_list("pk", flat=True)

            filestore_cats = Category.objects.filter(
                categorytransformation__key=ACTION.value, categorytransformation__value=A_FILESTORE.value
            ).values_list("pk", flat=True)

            none_cats = Category.objects.filter(
                categorytransformation__key=ACTION.value, categorytransformation__value=A_NONE.value
            ).values_list("pk", flat=True)

            bypass_cats = Category.objects.filter(
                categorytransformation__key=ACTION.value, categorytransformation__value=A_BYPASS.value
            ).values_list("pk", flat=True)

            # Lateral
            cat_l_auto = Category.objects.filter(
                categorytransformation__key=LATERAL.value, categorytransformation__value=L_AUTO.value
            ).values_list("pk", flat=True)

            cat_l_yes = Category.objects.filter(
                categorytransformation__key=LATERAL.value, categorytransformation__value=L_YES.value
            ).values_list("pk", flat=True)

            cat_l_no = Category.objects.filter(
                categorytransformation__key=LATERAL.value, categorytransformation__value=L_NO.value
            ).values_list("pk", flat=True)

            # Target
            cat_t_auto = Category.objects.filter(
                categorytransformation__key=TARGET.value, categorytransformation__value=T_AUTO.value
            ).values_list("pk", flat=True)

            cat_t_src = Category.objects.filter(
                categorytransformation__key=TARGET.value, categorytransformation__value=T_SOURCE.value
            ).values_list("pk", flat=True)

            cat_t_dst = Category.objects.filter(
                categorytransformation__key=TARGET.value, categorytransformation__value=T_DST.value
            ).values_list("pk", flat=True)

            cat_t_none = Category.objects.filter(
                categorytransformation__key=TARGET.value, categorytransformation__value=T_NONE.value
            ).values_list("pk", flat=True)

            # #### Rulesets
            # Actions
            drop_rulesets = Ruleset.objects.filter(
                rulesettransformation__key=ACTION.value, rulesettransformation__value=A_DROP.value
            ).values_list("pk", flat=True)

            reject_rulesets = Ruleset.objects.filter(
                rulesettransformation__key=ACTION.value, rulesettransformation__value=A_REJECT.value
            ).values_list("pk", flat=True)

            filestore_rulesets = Ruleset.objects.filter(
                rulesettransformation__key=ACTION.value, rulesettransformation__value=A_FILESTORE.value
            ).values_list("pk", flat=True)

            bypass_rulesets = Ruleset.objects.filter(
                rulesettransformation__key=ACTION.value, rulesettransformation__value=A_BYPASS.value
            ).values_list("pk", flat=True)

            # Lateral
            ruleset_l_auto = Ruleset.objects.filter(
                rulesettransformation__key=LATERAL.value, rulesettransformation__value=L_AUTO.value
            ).values_list("pk", flat=True)

            ruleset_l_yes = Ruleset.objects.filter(
                rulesettransformation__key=LATERAL.value, rulesettransformation__value=L_YES.value
            ).values_list("pk", flat=True)

            # Target
            ruleset_t_auto = Ruleset.objects.filter(
                rulesettransformation__key=TARGET.value, rulesettransformation__value=T_AUTO.value
            ).values_list("pk", flat=True)

            ruleset_t_src = Ruleset.objects.filter(
                rulesettransformation__key=TARGET.value, rulesettransformation__value=T_SOURCE.value
            ).values_list("pk", flat=True)

            ruleset_t_dst = Ruleset.objects.filter(
                rulesettransformation__key=TARGET.value, rulesettransformation__value=T_DST.value
            ).values_list("pk", flat=True)

            # Set rules action cache
            cls.TRANSFORMATIONS[ACTION][rule_str][A_DROP] = set(drop_rules)
            cls.TRANSFORMATIONS[ACTION][rule_str][A_REJECT] = set(reject_rules)
            cls.TRANSFORMATIONS[ACTION][rule_str][A_FILESTORE] = set(filestore_rules)
            cls.TRANSFORMATIONS[ACTION][rule_str][A_NONE] = set(none_rules)
            cls.TRANSFORMATIONS[ACTION][rule_str][A_BYPASS] = set(bypass_rules)

            cls.TRANSFORMATIONS[LATERAL][rule_str][L_AUTO] = set(rule_l_auto)
            cls.TRANSFORMATIONS[LATERAL][rule_str][L_YES] = set(rule_l_yes)
            cls.TRANSFORMATIONS[LATERAL][rule_str][L_NO] = set(rule_l_no)

            cls.TRANSFORMATIONS[TARGET][rule_str][T_AUTO] = set(rule_t_auto)
            cls.TRANSFORMATIONS[TARGET][rule_str][T_SOURCE] = set(rule_t_src)
            cls.TRANSFORMATIONS[TARGET][rule_str][T_DST] = set(rule_t_dst)
            cls.TRANSFORMATIONS[TARGET][rule_str][T_NONE] = set(rule_t_none)

            # set categories action cache
            cls.TRANSFORMATIONS[ACTION][category_str][A_DROP] = set(drop_cats)
            cls.TRANSFORMATIONS[ACTION][category_str][A_REJECT] = set(reject_cats)
            cls.TRANSFORMATIONS[ACTION][category_str][A_FILESTORE] = set(filestore_cats)
            cls.TRANSFORMATIONS[ACTION][category_str][A_BYPASS] = set(bypass_cats)
            cls.TRANSFORMATIONS[ACTION][category_str][A_NONE] = set(none_cats)

            cls.TRANSFORMATIONS[LATERAL][category_str][L_AUTO] = set(cat_l_auto)
            cls.TRANSFORMATIONS[LATERAL][category_str][L_YES] = set(cat_l_yes)
            cls.TRANSFORMATIONS[LATERAL][category_str][L_NO] = set(cat_l_no)

            cls.TRANSFORMATIONS[TARGET][category_str][T_AUTO] = set(cat_t_auto)
            cls.TRANSFORMATIONS[TARGET][category_str][T_SOURCE] = set(cat_t_src)
            cls.TRANSFORMATIONS[TARGET][category_str][T_DST] = set(cat_t_dst)
            cls.TRANSFORMATIONS[TARGET][category_str][T_NONE] = set(cat_t_none)

            # set rulesets action cache
            cls.TRANSFORMATIONS[ACTION][ruleset_str][A_DROP] = set(drop_rulesets)
            cls.TRANSFORMATIONS[ACTION][ruleset_str][A_REJECT] = set(reject_rulesets)
            cls.TRANSFORMATIONS[ACTION][ruleset_str][A_FILESTORE] = set(filestore_rulesets)
            cls.TRANSFORMATIONS[ACTION][ruleset_str][A_BYPASS] = set(bypass_rulesets)

            cls.TRANSFORMATIONS[LATERAL][ruleset_str][L_AUTO] = set(ruleset_l_auto)
            cls.TRANSFORMATIONS[LATERAL][ruleset_str][L_YES] = set(ruleset_l_yes)

            cls.TRANSFORMATIONS[TARGET][ruleset_str][T_AUTO] = set(ruleset_t_auto)
            cls.TRANSFORMATIONS[TARGET][ruleset_str][T_SOURCE] = set(ruleset_t_src)
            cls.TRANSFORMATIONS[TARGET][ruleset_str][T_DST] = set(ruleset_t_dst)

        else:
            raise Exception("Rule cache has not been closed")

    @classmethod
    def disable_cache(cls):
        if cls.TRANSFORMATIONS != {}:
            del cls.TRANSFORMATIONS
            cls.TRANSFORMATIONS = {}
        else:
            raise Exception("%s cache has not been open" % cls.__name__)


class Category(models.Model, Transformable, Cache):
    name = models.CharField(max_length=100)
    filename = models.CharField(max_length=200)
    descr = models.CharField(max_length=400, blank=True)
    created_date = models.DateTimeField("date created", default=timezone.now)
    source = models.ForeignKey(Source, on_delete=models.CASCADE)

    class Meta:
        verbose_name_plural = "categories"

    def __str__(self):
        return self.name

    def __init__(self, *args, **kwargs):
        models.Model.__init__(self, *args, **kwargs)
        Cache.__init__(self)

    @staticmethod
    def get_icon():
        return "fa-list-alt"

    def build_sigs_group(self, existing_rules_hash):
        sigs_groups = {}

        # build hash on message
        ravs = existing_rules_hash.get("groups", {}).get(self.name, [])
        for rav in ravs:
            # let's get the new IP only, will output that as text field at save time
            rule = rav.rule
            rule.ips_list = set()
            sigs_groups[rule.msg] = {"rule": rule, "rav": rav}
        return sigs_groups

    def parse_group_signature(self, group_rule, rule):
        if group_rule.group_by == "by_src":
            ips_list = Rule.IPSREGEXP["src"].findall(rule.header)[0]
        else:
            ips_list = Rule.IPSREGEXP["dest"].findall(rule.header)[0]
        if ips_list.startswith("["):
            ips_list = ips_list[1:-1].split(",")
        else:
            ips_list = [
                ips_list,
            ]
        group_rule.ips_list.update(ips_list)
        group_rule.next_rev = rule.rev

    def add_group_signature(
        self, sigs_groups, line, existing_rules_hash, source, flowbits, rules_update, rules_unchanged
    ):
        # parse the line with ids tools
        try:
            rule = rule_idstools.parse(line)
        except Exception:
            return
        if rule is None:
            return

        # version is always at 0 here while versioning is done on stamus source only
        version = 0
        rule_base_msg = Rule.GROUPSNAMEREGEXP.findall(rule.msg)[0]
        ips_list = Rule.IPSREGEXP["src"].findall(rule.header)[0]
        track_by = "src" if ips_list.startswith("[") else "dst"
        content = rule.raw
        iprep_group = rule.sid

        content = content.replace(";)", "; iprep:%s,%s,>,1;)" % (track_by, iprep_group))
        # replace IP list by any
        content = re.sub(r"\[\d+.*\d+\]", r"any", content)
        # fix message
        content = re.sub(r'msg:".*";', r'msg:"%s";' % rule_base_msg, content)

        # check if we already have a signature in the group signatures
        # that match
        if rule_base_msg in sigs_groups:
            # TODO coherence check
            # add IPs to the list if revision has changed
            rav = sigs_groups[rule_base_msg]["rav"]
            group_rule = sigs_groups[rule_base_msg]["rule"]

            if content != rav.content:
                self.parse_group_signature(group_rule, rule)
                # Is there an existing rule to clean ? this is needed at
                # conversion of source to use iprep but we will have a different
                # message in this case (with group)
                if rule.sid in existing_rules_hash and version in existing_rules_hash[rule.sid]:
                    # the sig is already present and it is a group sid so let's declare it
                    # updated to avoid its deletion later in process. No else clause because
                    # the signature will be deleted as it is not referenced in a changed or
                    # unchanged list
                    if rule_base_msg == existing_rules_hash[rule.sid][version].rule.msg:
                        rules_update["updated"].append(existing_rules_hash[rule.sid][version].rule)
            else:
                rules_unchanged.append(group_rule)
        else:
            creation_date = timezone.now()
            state = True
            if rule.raw.startswith("#"):
                state = False

            # if we already have a signature with the SID we are probably parsing
            # a source that has just been switched to iprep. So we get the old
            # rule and we update the content to avoid loosing information.
            if rule.sid in existing_rules_hash and version in existing_rules_hash[rule.sid]:
                rav = existing_rules_hash[rule.sid][version]
                group_rule = rav.rule
                group_rule.group = True
                group_rule.msg = rule_base_msg
                rav.content = content
                rav.updated_date = creation_date
                rav.rev = rule.rev

                if rav.state != rav.commented_in_source and rav.commented_in_source == state:
                    rav.state = state
                rav.commented_in_source = not state
                rav.save()
                rules_update["updated"].append(group_rule)
            else:
                group_rule = Rule(
                    category=self,
                    sid=rule.sid,
                    group=True,
                    msg=rule_base_msg,
                )

                rav = RuleAtVersion(
                    rule=group_rule,
                    rev=rule.rev - 1,
                    version=version,
                    content=line,
                    state=state,
                    commented_in_source=not state,
                    imported_date=creation_date,
                    updated_date=creation_date,
                )

                rav.parse_metadata()
                rav.parse_flowbits(source, flowbits, addition=True)
                rules_update["updated"].append(group_rule)
                rules_update["ravs"].append(rav)
            if track_by == "src":
                group_rule.group_by = "by_src"
            else:
                group_rule.group_by = "by_dest"
            group_rule.ips_list = set()
            self.parse_group_signature(group_rule, rule)
            sigs_groups[group_rule.msg] = {"rule": group_rule, "rav": rav}

    def get_rules(self, source, version=0, filename=None, existing_rules_hash=None):
        # parse file
        # return an object with updates
        getsid = re.compile(r"sid *: *(\d+)")
        getrev = re.compile(r"rev *: *(\d+)")
        getmsg = re.compile(r"msg *: *\"(.*?)\"")
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.source.pk))

        if filename is None:
            filename = self.filename

        rules_update = {"added": [], "deleted": [], "updated": [], "ravs": []}
        flowbits = {"added": {"flowbit": [], "through_set": [], "through_isset": []}}
        rules_unchanged = []

        if existing_rules_hash is None:
            existing_rules_hash = {"groups": {}}
            for rav in (
                RuleAtVersion.objects.filter(rule__category__source=self.source)
                .prefetch_related("rule")
                .prefetch_related("rule__category")
                .prefetch_related("rule__category__source")
            ):
                rule = rav.rule
                if rule.sid not in existing_rules_hash:
                    existing_rules_hash[rule.sid] = {}

                existing_rules_hash[rule.sid][rav.version] = rav

                if source.use_iprep and rule.group:
                    if rule.category.name not in existing_rules_hash["groups"]:
                        existing_rules_hash["groups"][rule.category.name] = []
                    existing_rules_hash["groups"][rule.category.name].append(rav)

        rules_list = Rule.objects.filter(
            sid__in=RuleAtVersion.objects.filter(rule__category=self, version=version).values_list(
                "rule__sid", flat=True
            )
        )

        for key in ("flowbits", "hostbits", "xbits"):
            flowbits[key] = {}
            for flowb in Flowbit.objects.filter(source=source, type=key):
                flowbits[key][flowb.name] = flowb

        creation_date = timezone.now()

        rules_groups = {}
        if source.use_iprep:
            rules_groups = self.build_sigs_group(existing_rules_hash)

        with open(os.path.join(source_git_dir, filename)) as rfile:
            with transaction.atomic():
                for line in rfile:
                    state = True
                    if line.startswith("#"):
                        # check if it is a commented signature
                        if "->" in line and "sid" in line and ")" in line:
                            line = line.lstrip("# ")
                            state = False
                        else:
                            continue
                    match = getsid.search(line)
                    if not match:
                        continue
                    sid_str = match.groups()[0]
                    match = getrev.search(line)
                    if match:
                        rev = int(match.groups()[0])
                    else:
                        rev = None
                    match = getmsg.search(line)
                    if not match:
                        msg = ""
                    else:
                        msg = match.groups()[0]
                        # length of message could exceed 1000 so truncate
                        if len(msg) > 1000:
                            msg = msg[0:999]

                    if source.use_iprep and Rule.GROUPSNAMEREGEXP.match(msg):
                        self.add_group_signature(
                            rules_groups, line, existing_rules_hash, source, flowbits, rules_update, rules_unchanged
                        )
                    else:
                        sid = int(sid_str)
                        if sid in existing_rules_hash and version in existing_rules_hash[sid]:
                            # FIXME update references if needed
                            rav = existing_rules_hash[sid][version]
                            rule = rav.rule

                            if rule.category.source != source:
                                raise DuplicateSidException(sid)

                            # check if rav has been saved,
                            # if not it means rules with duplicate sids in same source
                            if rav.pk is None:
                                raise DuplicateSidException(sid, same_source=True)

                            if (
                                rav.content != line or rule.group is True or (rav.state != rav.commented_in_source and rav.commented_in_source == state)
                            ):
                                rav.content = line

                                if rav.state != rav.commented_in_source and rav.commented_in_source == state:
                                    rav.state = state
                                rav.commented_in_source = not state

                                rav.rev = 0 if rev is None else rev
                                rav.parse_metadata()
                                rav.parse_flowbits(source, flowbits)
                                rav.updated_date = creation_date
                                rav.save()

                                if rule.category != self:
                                    rule.category = self

                                if rule.msg != msg:
                                    rule.msg = msg

                                rule.save()
                                rules_update["updated"].append(rule)

                            else:
                                rules_unchanged.append(rule)
                        else:
                            if rev is None:
                                rev = 0

                            if sid in existing_rules_hash:
                                rule = list(existing_rules_hash[sid].values())[0].rule
                                rules_update["updated"].append(rule)
                            else:
                                rule = Rule(
                                    category=self,
                                    sid=sid,
                                    msg=msg,
                                )
                                existing_rules_hash[rule.sid] = {}

                                try:
                                    rule.clean()
                                    # we avoid foreign key / pk (sid) to not call DB
                                    # on each rule
                                    rule.full_clean(exclude=("category", "sid"))
                                except ValidationError as e:
                                    err = {"sid_": rule.sid}
                                    err.update(e.message_dict)
                                    raise ValidationError(err)

                                rules_update["added"].append(rule)

                            rav = RuleAtVersion(
                                rule=rule,
                                rev=rev,
                                version=version,
                                content=line,
                                state=state,
                                commented_in_source=not state,
                                imported_date=creation_date,
                                updated_date=creation_date,
                            )

                            rav.parse_metadata()
                            rav.parse_flowbits(source, flowbits, addition=True)
                            rules_update["ravs"].append(rav)
                            existing_rules_hash[rule.sid][rav.version] = rav

                if len(rules_update["added"]):
                    try:
                        Rule.objects.bulk_create(rules_update["added"])
                    except IntegrityError as e:
                        error = str(e)
                        match = re.search(r"\(sid\)=\((\d+)\)", error)
                        sid = ""
                        if match:
                            sid = match.group(1)
                        raise DuplicateSidException(sid)

                if len(rules_update["ravs"]):
                    # We cannot validate before like rules,
                    # because rules need to be saved first
                    for rav in rules_update["ravs"]:
                        try:
                            rav.clean()
                            rav.full_clean(exclude=("rule",))
                        except ValidationError as e:
                            err = {"sid_": rav.rule.sid}
                            err.update(e.message_dict)
                            raise ValidationError(err)

                    RuleAtVersion.objects.bulk_create(rules_update["ravs"])

                if len(rules_groups):
                    for val in rules_groups.values():
                        # If IP list is empty it will be deleted because it has not
                        # been put in a changed or unchanged list. So we just care
                        # about saving the rule.
                        rav = val["rav"]
                        rule = val["rule"]

                        if len(rule.ips_list) > 0:
                            rule.group_ips_list = ",".join(rule.ips_list)
                            rule.save()
                            rav.rev = rule.next_rev
                            rav.save()

                            if rule.category.name not in existing_rules_hash["groups"]:
                                existing_rules_hash["groups"][rule.category.name] = []
                            existing_rules_hash["groups"][rule.category.name].append(rav)

                if len(flowbits["added"]["flowbit"]):
                    Flowbit.objects.bulk_create(flowbits["added"]["flowbit"])
                if len(flowbits["added"]["through_set"]):
                    Flowbit.set.through.objects.bulk_create(flowbits["added"]["through_set"])
                if len(flowbits["added"]["through_isset"]):
                    Flowbit.isset.through.objects.bulk_create(flowbits["added"]["through_isset"])
                rules_update["deleted"] = list(
                    set(rules_list) - set(rules_update["added"]).union(set(rules_update["updated"])) - set(rules_unchanged)
                )
                source.aggregate_update(rules_update)

    def get_absolute_url(self):
        return reverse("category", args=[str(self.id)])

    def enable(self, ruleset, request=None, comment=None):
        ruleset.categories.add(self)
        if request:
            UserAction.create(
                action_type="enable_category", comment=comment, request=request, category=self, ruleset=ruleset
            )

    def disable(self, ruleset, request=None, comment=None):
        ruleset.categories.remove(self)
        if request:
            UserAction.create(
                action_type="disable_category", comment=comment, request=request, category=self, ruleset=ruleset
            )

    def is_transformed(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        if Category.TRANSFORMATIONS == {}:
            return self.pk in ruleset.get_transformed_categories(key=key, value=value).values_list("pk", flat=True)

        category_str = Category.__name__.lower()
        return self.pk in Category.TRANSFORMATIONS[key][category_str][value]

    def suppress_transformation(self, ruleset, key):
        CategoryTransformation.objects.filter(ruleset=ruleset, category_transformation=self, key=key.value).delete()

    def toggle_transformation(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        if self.is_transformed(ruleset, key=key, value=value):
            CategoryTransformation.objects.filter(ruleset=ruleset, category_transformation=self, key=key.value).delete()
        else:
            c = CategoryTransformation(ruleset=ruleset, category_transformation=self, key=key.value, value=value.value)
            c.save()

    def get_transformation(self, ruleset, key=Transformation.ACTION, override=False):
        TYPE = None

        if key == Transformation.ACTION:
            TYPE = Transformation.ActionTransfoType
        elif key == Transformation.LATERAL:
            TYPE = Transformation.LateralTransfoType
        elif key == Transformation.TARGET:
            TYPE = Transformation.TargetTransfoType
        else:
            raise Exception("Key '%s' is unknown" % key)

        if Category.TRANSFORMATIONS == {}:
            ct = CategoryTransformation.objects.filter(key=key.value, ruleset=ruleset, category_transformation=self)
            if ct.count() > 0:
                return TYPE(ct[0].value)

            if override:
                rt = RulesetTransformation.objects.filter(key=key.value, ruleset_transformation=ruleset)
                if rt.count() > 0:
                    return TYPE(rt[0].value)

        else:
            # This code is currently dead, not reachable from UI
            # but it can be called from django shell
            category_str = Category.__name__.lower()
            ruleset_str = Ruleset.__name__.lower()

            for trans, tsets in Category.TRANSFORMATIONS[key][category_str].items():
                if self.pk in tsets:  # DROP / REJECT / FILESTORE / NONE
                    return trans

            if override:
                for trans, tsets in Category.TRANSFORMATIONS[key][ruleset_str].items():
                    if tsets and ruleset.pk in tsets:
                        return trans

        return None

    @staticmethod
    def get_transformation_choices(key=Transformation.ACTION):
        # Keys
        ACTION = Transformation.ACTION
        LATERAL = Transformation.LATERAL
        TARGET = Transformation.TARGET

        allowed_choices = []

        if key == ACTION:
            all_choices_set = set(Transformation.ActionTransfoType.get_choices())
            allowed_choices = list(all_choices_set.intersection(set(settings.RULESET_TRANSFORMATIONS)))

            A_BYPASS = Transformation.A_BYPASS
            A_RULESET_DEFAULT = Transformation.A_RULESET_DEFAULT
            A_NONE = Transformation.A_NONE

            # TODO: move me in settings.RULESET_TRANSFORMATIONS
            allowed_choices.append((A_BYPASS.value, A_BYPASS.name.title()))
            allowed_choices.append((A_RULESET_DEFAULT.value, A_RULESET_DEFAULT.name.replace("_", " ").title()))
            allowed_choices.append((A_NONE.value, A_NONE.name.title()))

        if key == TARGET:
            CAT_DEFAULT = Transformation.T_CAT_DEFAULT
            allowed_choices = list(Transformation.TargetTransfoType.get_choices())
            allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace("_", " ").title()))

        if key == LATERAL:
            CAT_DEFAULT = Transformation.L_CAT_DEFAULT
            allowed_choices = list(Transformation.LateralTransfoType.get_choices())
            allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace("_", " ").title()))

        return tuple(sorted(allowed_choices))


class RangeCheckIntegerFields(models.Model):
    MIN = -2147483648
    MAX = 2147483647

    class Meta:
        abstract = True

    def clean(self):
        for field in self._meta.fields:
            if field.__class__ == models.IntegerField:
                value = getattr(self, field.name)
                if value < self.MIN or value > self.MAX:
                    raise ValidationError({f"{field.name}": f'"{value}" is out of range'})


class Reference:
    def __init__(self, key, value):
        self.value = value
        self.key = key
        self.url = None


class Rule(RangeCheckIntegerFields, Transformable, Cache):
    GROUP_BY_CHOICES = (("by_src", "by_src"), ("by_dst", "by_dst"))
    sid = models.BigIntegerField(primary_key=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    msg = models.CharField(max_length=1000)
    group = models.BooleanField(default=False)
    group_by = models.CharField(max_length=10, choices=GROUP_BY_CHOICES, default="by_src")
    group_ips_list = models.TextField(blank=True, null=True)  # store one IP per line
    created = models.DateField(blank=True, null=True)
    updated = models.DateField(blank=True, null=True)

    hits = 0

    IPSREGEXP = {"src": re.compile(r"^\S+ +\S+ (.*) +\S+ +\->"), "dest": re.compile(r"\-> (.*) +\S+$")}

    GROUPSNAMEREGEXP = re.compile(r"^(.*) +group +\d+$")

    READ_ONLY_SIDS = (999999999,)

    # initialized in AppConfig or when adding stamus source or stay empty
    SID_RANGES = {}

    IOC_RANGE = [3120786, 3120985]

    def __str__(self):
        return str(self.sid) + ":" + self.msg

    def __init__(self, *args, **kwargs):
        models.Model.__init__(self, *args, **kwargs)
        Cache.__init__(self)

    @classmethod
    def get_ioc_next_sid(cls) -> int:
        return (
            cls.objects.filter(  # pyright: ignore
                sid__range=cls.IOC_RANGE
            )
            .aggregate(
                # remove 1 because we add 1 in the next line
                max_sid=Coalesce(models.Max("sid"), cls.IOC_RANGE[0] - 1)
            )
            .get("max_sid") + 1
        )

    def is_in_stamus_range(self):
        for values in self.SID_RANGES.values():
            for arr in values.values():
                for item in arr:
                    if item["min"] <= self.sid <= item["max"]:
                        name = f"({item.get('name', '')})"
                        raise ValidationError({"sid": f'"{self.sid}" is in Stamus ranges {name}'})

    @classmethod
    def get_last_real_version(cls, version, **kwargs):
        if cls.objects.exists():
            return (
                cls.objects.filter(ruleatversion__version__range=[0, version], **kwargs)
                .aggregate(max_version=models.Max("ruleatversion__version", default=0))
                .get("max_version", 0)
            )
        return version

    def clean(self):
        super().clean()
        # check stamus ranges
        if not self.category.source.is_stamus:
            self.is_in_stamus_range()

    def can_drop(self):
        """
        True if one of the rule at version is True
        """
        for rav in self.ruleatversion_set.all():
            if rav.can_drop():
                return True
        return False

    def can_filestore(self):
        """
        True if one of the rule at version is True
        """
        for rav in self.ruleatversion_set.all():
            if rav.can_filestore():
                return True
        return False

    def can_lateral(self):
        """
        True if one of the rule at version is True
        """
        return any(rav.can_lateral() for rav in self.ruleatversion_set.all())

    def can_target(self):
        """
        True if one of the rule at version is True
        """
        for rav in self.ruleatversion_set.all():
            if rav.can_target():
                return True
        return False

    def are_ravs_synched(self):
        nb = 0
        max = self.ruleatversion_set.count()
        for rav in self.ruleatversion_set.all():
            if not rav.state:
                nb += 1
        return nb == 0 or nb == max

    def are_ravs_all_commented(self):
        nb = 0
        max = self.ruleatversion_set.count()
        for rav in self.ruleatversion_set.all():
            if rav.commented_in_source:
                nb += 1
        return nb == max

    @property
    def name(self):
        return str(self)

    @staticmethod
    def get_icon():
        return "pficon-security"

    def get_absolute_url(self):
        return reverse("rule", args=[str(self.sid)])

    def get_actions(self, user):
        history = UserAction.objects.filter(
            user_action_objects__content_type=ContentType.objects.get_for_model(Rule),
            user_action_objects__object_id=self.pk,
        ).order_by("-date")

        res = []
        for item in history:
            res.append(
                {
                    "description": item.generate_description(user),
                    "comment": item.comment,
                    "title": item.get_title(),
                    "date": item.date,
                    "icons": item.get_icons(),
                    "client_ip": item.client_ip,
                }
            )
        return res

    def get_comments(self):
        return UserAction.objects.filter(
            action_type__in=[
                "comment_rule",
                "transform_rule",
                "enable_rule",
                "suppress_rule",
                "disable_rule",
                "delete_suppress_rule",
            ],
            user_action_objects__content_type=ContentType.objects.get_for_model(Rule),
            user_action_objects__object_id=self.pk,
        ).order_by("-date")

    def get_dependant_rules_at_version(self, ruleset):
        ravs = []
        for rav in self.ruleatversion_set.all():
            ravs.append(rav)
            ravs.extend(rav.get_dependant_rules_at_version(ruleset))
        return ravs

    def enable(self, ruleset, request=None, comment=None):
        ruleset.enable_rules_at_version(self.get_dependant_rules_at_version(ruleset))
        if request:
            UserAction.create(action_type="enable_rule", comment=comment, request=request, rule=self, ruleset=ruleset)

    def disable(self, ruleset, request=None, comment=None):
        ruleset.disable_rules_at_version(self.get_dependant_rules_at_version(ruleset))
        if request:
            UserAction.create(action_type="disable_rule", comment=comment, request=request, rule=self, ruleset=ruleset)

    def test(self, ruleset):
        try:
            self.enable_cache()
            test = ruleset.test_rule_buffer(self.generate_content(ruleset))
        except Exception:
            return False
        finally:
            self.disable_cache()
        return test

    def toggle_availability(self, version=None):
        ravs = self.ruleatversion_set.filter(version=version) if version is not None else self.ruleatversion_set.all()

        for rav in ravs:
            rav.toggle_availability()

    def apply_transformation(self, content, key=Transformation.ACTION, value=None):
        if key == Transformation.ACTION:
            if value == Transformation.A_REJECT:
                content = re.sub(r"^ *\S+", "reject", content)
            elif value == Transformation.A_DROP:
                content = re.sub(r"^ *\S+", "drop", content)
            elif value == Transformation.A_FILESTORE:
                content = re.sub(r"; *\)", "; filestore;)", content)
            elif value == Transformation.A_BYPASS:
                if "noalert" in content:
                    content = re.sub(r"; noalert;", "; noalert; bypass;", content)
                else:
                    content = re.sub(r"; *\)$", "; noalert; bypass;)", content)
                content = re.sub(r"^ *\S+", "pass", content)

        elif key == Transformation.LATERAL or key == Transformation.TARGET:
            content = self.apply_lateral_target_transfo(content, key, value)

        return content

    def is_transformed(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        if Rule.TRANSFORMATIONS == {}:
            return self in ruleset.get_transformed_rules(key=key, value=value).values_list("pk", flat=True)

        rule_str = Rule.__name__.lower()
        return self.pk in Rule.TRANSFORMATIONS[key][rule_str][value]

    def get_transformation(self, ruleset, key=Transformation.ACTION, override=False):
        TYPE = None

        if key == Transformation.ACTION:
            TYPE = Transformation.ActionTransfoType
        elif key == Transformation.LATERAL:
            TYPE = Transformation.LateralTransfoType
        elif key == Transformation.TARGET:
            TYPE = Transformation.TargetTransfoType
        else:
            raise Exception("Key '%s' is unknown" % key)

        if Rule.TRANSFORMATIONS == {}:
            rt = RuleTransformation.objects.filter(key=key.value, ruleset=ruleset, rule_transformation=self).all()

            if rt.count() > 0:
                return TYPE(rt[0].value)

            if override:
                ct = CategoryTransformation.objects.filter(
                    key=key.value, ruleset=ruleset, category_transformation=self.category
                ).all()

                if ct.count() > 0:
                    return TYPE(ct[0].value)

                rt = RulesetTransformation.objects.filter(key=key.value, ruleset_transformation=ruleset)
                if rt.count() > 0:
                    return TYPE(rt[0].value)

        else:
            rule_str = Rule.__name__.lower()
            category_str = Category.__name__.lower()
            ruleset_str = Ruleset.__name__.lower()

            for trans, tsets in Rule.TRANSFORMATIONS[key][rule_str].items():
                if tsets is not None and tsets and self.pk in tsets:
                    return trans

            if override:
                for trans, tsets in Rule.TRANSFORMATIONS[key][category_str].items():
                    if tsets is not None and tsets and self.category.pk in tsets:
                        return trans

                for trans, tsets in Rule.TRANSFORMATIONS[key][ruleset_str].items():
                    if tsets is not None and tsets and ruleset.pk in tsets:
                        return trans

        return None

    def remove_transformations(self, ruleset, key):
        RuleTransformation.objects.filter(ruleset=ruleset, rule_transformation=self, key=key.value).delete()

        ruleset.save()

    def set_transformation(self, ruleset, key=Transformation.ACTION, value=Transformation.A_DROP):
        self.remove_transformations(ruleset, key)

        r = RuleTransformation(ruleset=ruleset, rule_transformation=self, key=key.value, value=value.value)
        r.save()

        ruleset.save()

    def is_untrusted(self):
        try:
            return self.untrusted
        except Exception:
            logger.debug("Untrusted rule", sid=self.sid)
        return self.category.source.untrusted

    def generate_content(self, ruleset, version=0):
        try:
            rule_at_version = self.ruleatversion_set.get(version=version)
        except self.DoesNotExist:
            request_logger.warning("Rule %s at version %s does not exist" % (self.pk, version))
            return ""
        return rule_at_version.generate_content(ruleset)

    def get_transformation_choices(self, key=Transformation.ACTION):
        # Keys
        ACTION = Transformation.ACTION
        LATERAL = Transformation.LATERAL
        TARGET = Transformation.TARGET

        allowed_choices = []

        if key == ACTION:
            all_choices_set = set(Transformation.ActionTransfoType.get_choices())
            allowed_choices = list(all_choices_set.intersection(set(settings.RULESET_TRANSFORMATIONS)))

            A_DROP = Transformation.A_DROP
            A_FILESTORE = Transformation.A_FILESTORE
            A_REJECT = Transformation.A_REJECT
            A_BYPASS = Transformation.A_BYPASS
            A_NONE = Transformation.A_NONE
            A_CATEGORY = Transformation.A_CAT_DEFAULT

            # Remove not allowed actions
            if not self.can_drop():
                if (A_DROP.value, A_DROP.name.title()) in allowed_choices:
                    allowed_choices.remove((A_DROP.value, A_DROP.name.title()))

                if (A_REJECT.value, A_REJECT.name.title()) in allowed_choices:
                    allowed_choices.remove((A_REJECT.value, A_REJECT.name.title()))

            if not self.can_filestore():
                if (A_FILESTORE.value, A_FILESTORE.name.title()) in allowed_choices:
                    allowed_choices.remove((A_FILESTORE.value, A_FILESTORE.name.title()))

            # Test with Bypass transformation
            # TODO: move me in settings.RULESET_TRANSFORMATIONS
            allowed_choices.append((A_BYPASS.value, A_BYPASS.name.title()))

            # Add None/Category actions (Only for Rules)
            allowed_choices.append((A_CATEGORY.value, A_CATEGORY.name.replace("_", " ").title()))
            allowed_choices.append((A_NONE.value, A_NONE.name.title()))

        elif key == TARGET:
            RULESET_DEFAULT = Transformation.T_RULESET_DEFAULT

            allowed_choices = list(Transformation.TargetTransfoType.get_choices())
            allowed_choices.remove((RULESET_DEFAULT.value, RULESET_DEFAULT.name.replace("_", " ").title()))
            # Workaround (self.target): ref #674
            # Cannot transform, idstools cannot parse it
            # So remove this transformation from choices
            if not self.can_target():
                T_AUTO = Transformation.T_AUTO
                T_SOURCE = Transformation.T_SOURCE
                T_DEST = Transformation.T_DESTINATION

                for trans in (T_AUTO, T_SOURCE, T_DEST):
                    allowed_choices.remove((trans.value, trans.name.title()))

        elif key == LATERAL:
            RULESET_DEFAULT = Transformation.L_RULESET_DEFAULT

            allowed_choices = list(Transformation.LateralTransfoType.get_choices())
            allowed_choices.remove((RULESET_DEFAULT.value, RULESET_DEFAULT.name.replace("_", " ").title()))

            L_YES = Transformation.L_YES
            L_AUTO = Transformation.L_AUTO

            if not self.can_lateral():
                for trans in (L_YES, L_AUTO):
                    allowed_choices.remove((trans.value, trans.name.title()))

        return tuple(allowed_choices)

    def extract_rule_references(self):
        references = []
        for ref in re.findall(r"reference: *(\w+), *(\S+);", self.ruleatversion_set.first().content):
            refer = Reference(ref[0], ref[1])
            if refer.key == "url":
                if not refer.value.startswith("http"):
                    refer.url = "http://" + refer.value
                else:
                    refer.url = refer.value
            elif refer.key == "cve":
                refer.url = "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-" + refer.value
                refer.key = refer.key.upper()
            elif refer.key == "bugtraq":
                refer.url = "http://www.securityfocus.com/bid/" + refer.value
            references.append(refer)
        return references


def build_iprep_name(msg):
    return re.sub("[^0-9a-zA-Z]+", "_", msg.replace(" ", ""))


class RuleAtVersion(RangeCheckIntegerFields):
    rule = models.ForeignKey(Rule, on_delete=models.CASCADE)
    rev = models.IntegerField(default=0)
    version = models.IntegerField(default=0)
    content = models.CharField(max_length=10000)
    state = models.BooleanField(default=True)
    commented_in_source = models.BooleanField(default=False)

    imported_date = models.DateTimeField(default=timezone.now)
    updated_date = models.DateTimeField(default=timezone.now)
    created = models.DateField(blank=True, null=True)
    updated = models.DateField(blank=True, null=True)
    analysis = models.TextField(blank=True, null=True)

    BITSREGEXP = {
        "flowbits": re.compile("flowbits *: *(isset|set),(.*?) *;"),
        "hostbits": re.compile("hostbits *: *(isset|set),(.*?) *;"),
        "xbits": re.compile("xbits *: *(isset|set),(.*?) *;"),
    }

    MANAGER_VERSION = None

    class Meta:
        unique_together = ("rule", "version")

    @classmethod
    def write_analyse(cls, content, version):
        ravs = cls.objects.select_related("rule").filter(rule__sid__in=content.keys(), version=version).all()

        for rav in ravs:
            msg = content[rav.rule.sid]
            msg.pop("raw")
            rav.analysis = json.dumps(msg)

        if ravs:
            RuleAtVersion.objects.bulk_update(ravs, ["analysis"], batch_size=1000)

    @classmethod
    def get_versions_to_analyse(cls):
        max_version = cls.MANAGER_VERSION
        all_versions = {0}
        if max_version and max_version >= 39:
            all_versions |= set(range(39, max_version + 1))
        return all_versions

    def is_active(self, ruleset):
        return self.state and self.rule.category in ruleset.categories.all() and not self.is_suppressed(ruleset)

    def is_suppressed(self, ruleset):
        return SuppressedRuleAtVersion.objects.filter(ruleset=ruleset, rule_at_version=self).count() > 0

    def get_dependant_rules_at_version(self, ruleset):
        """
        flowbit dependency:
        if we disable a rule that is the last one set a flag then we must disable all the
        dependant rules
        """
        # get list of flowbit we are setting
        flowbits_list = Flowbit.objects.filter(set=self).prefetch_related("set", "isset")
        dependant_ravs = []
        for flowbit in flowbits_list:
            set_count = 0
            for rav in flowbit.set.all():
                if rav == self:
                    continue
                if rav.is_active(ruleset):
                    set_count += 1
            if set_count == 0:
                dependant_ravs.extend(list(flowbit.isset.all()))
                # we need to recurse if ever we did disable in a chain of signatures
                for drav in flowbit.isset.all():
                    dependant_ravs.extend(drav.get_dependant_rules_at_version(ruleset))
        return set(dependant_ravs)

    def toggle_availability(self):
        self.state = not self.state
        self.save()

    def match_dataset(self):
        return re.match(r".* \(.*dataset:.*(save|state) .*;\)$", self.content)

    def match_luajit(self):
        return re.match(r".* \(.*(luajit|lua):.*;\)$", self.content)

    def can_drop(self):
        return "noalert" not in self.content

    def can_filestore(self):
        return self.content.split(" ")[1] in ("http", "smtp", "smb", "nfs", "ftp-data")

    def can_lateral(self):
        try:
            rule_ids = rule_idstools.parse(self.content)
        except Exception:
            return False
        # Workaround: ref #674
        # Cannot transform, idstools cannot parse it
        # So remove this transformation from choices
        if rule_ids is None or "outbound" in rule_ids["msg"].lower():
            return False

        return "$EXTERNAL_NET" in rule_ids.raw

    def can_target(self):
        try:
            rule_ids = rule_idstools.parse(self.content)
        except Exception:
            return False
        return rule_ids is not None

    def generate_content(self, ruleset):
        content = self.content

        if self.rule.is_untrusted() and (self.match_luajit() or self.match_dataset()):
            return f"disabled_as_source_is_untrusted: {content}"

        # explicitely set prio on transformation here
        # Action
        ACTION = Transformation.ACTION
        A_DROP = Transformation.A_DROP
        A_FILESTORE = Transformation.A_FILESTORE
        A_REJECT = Transformation.A_REJECT
        A_BYPASS = Transformation.A_BYPASS

        trans = self.rule.get_transformation(key=ACTION, ruleset=ruleset, override=True)
        if (
            (trans in (A_DROP, A_REJECT) and self.can_drop()) or (trans == A_FILESTORE and self.can_filestore()) or (trans == A_BYPASS)
        ):
            content = self.rule.apply_transformation(content, key=Transformation.ACTION, value=trans)

        # Lateral
        LATERAL = Transformation.LATERAL
        L_AUTO = Transformation.L_AUTO
        L_YES = Transformation.L_YES

        trans = self.rule.get_transformation(key=LATERAL, ruleset=ruleset, override=True)
        if trans in (L_YES, L_AUTO) and self.can_lateral():
            content = self.rule.apply_transformation(content, key=Transformation.LATERAL, value=trans)

        # Target
        TARGET = Transformation.TARGET
        T_SOURCE = Transformation.T_SOURCE
        T_DESTINATION = Transformation.T_DESTINATION
        T_AUTO = Transformation.T_AUTO

        trans = self.rule.get_transformation(key=TARGET, ruleset=ruleset, override=True)
        if trans in (T_SOURCE, T_DESTINATION, T_AUTO):
            content = self.rule.apply_transformation(content, key=Transformation.TARGET, value=trans)

        return content

    def parse_flowbits(self, source, flowbits, addition=False):
        for ftype in self.BITSREGEXP:
            match = self.BITSREGEXP[ftype].findall(self.content)
            if match:
                rule_flowbits = []
                for flowinst in match:
                    # avoid flowbit duplicate
                    if flowinst[1] not in rule_flowbits:
                        rule_flowbits.append(flowinst[1])
                    else:
                        continue
                    # create Flowbit if needed
                    if flowinst[1] not in list(flowbits[ftype].keys()):
                        elt = Flowbit(type=ftype, name=flowinst[1], source=source)
                        flowbits[ftype][flowinst[1]] = elt
                        flowbits["added"]["flowbit"].append(elt)
                    else:
                        elt = flowbits[ftype][flowinst[1]]

                    if flowinst[0] == "isset":
                        if addition or not self.checker.filter(isset=self):
                            through_elt = Flowbit.isset.through(flowbit=elt, rule_at_version=self)
                            flowbits["added"]["through_isset"].append(through_elt)
                    elif flowinst[0] == "set":
                        if addition or not self.setter.filter(set=self):
                            through_elt = Flowbit.set.through(flowbit=elt, rule_at_version=self)
                            flowbits["added"]["through_set"].append(through_elt)

    def parse_metadata_time(self, sfield):
        sdate = sfield.split(" ")[1]
        if sdate:
            de = sdate.split("_")
            try:
                return datetime_date(int(de[0]), int(de[1]), int(de[2]))
            except ValueError:
                # Catches conversion to int failure, in case the date is 'unknown'
                pass

        return None

    def parse_metadata(self):
        try:
            rule_ids = rule_idstools.parse(self.content)
        except Exception:
            return
        if rule_ids is None:
            return
        for meta in rule_ids.metadata:
            if meta.startswith("created_at "):
                self.created = self.parse_metadata_time(meta)
            if meta.startswith("updated_at "):
                self.updated = self.parse_metadata_time(meta)

        if self.rule.created is None or self.rule.created > self.created:
            self.rule.created = self.created

        if self.rule.updated is None or self.rule.updated < self.updated:
            self.rule.updated = self.updated


class Flowbit(models.Model):
    FLOWBIT_TYPE = (("flowbits", "Flowbits"), ("hostbits", "Hostbits"), ("xbits", "Xbits"))
    type = models.CharField(max_length=12, choices=FLOWBIT_TYPE)
    name = models.CharField(max_length=100)
    set = models.ManyToManyField(RuleAtVersion, related_name="setter", through="FlowbitSetRuleAtVersion")
    isset = models.ManyToManyField(RuleAtVersion, related_name="checker", through="FlowbitISSetRuleAtVersion")
    enable = models.BooleanField(default=True)
    source = models.ForeignKey(Source, on_delete=models.CASCADE)


class FlowbitSetRuleAtVersion(models.Model):
    """
    Intermediate table between Flowbits.set and Rule (pk)
    """

    flowbit = models.ForeignKey(Flowbit, on_delete=models.CASCADE)
    rule_at_version = models.ForeignKey(RuleAtVersion, on_delete=models.CASCADE)


class FlowbitISSetRuleAtVersion(models.Model):
    """
    Intermediate table between Flowbits.isset and Rule (pk)
    """

    flowbit = models.ForeignKey(Flowbit, on_delete=models.CASCADE)
    rule_at_version = models.ForeignKey(RuleAtVersion, on_delete=models.CASCADE)


# we should use django reversion to keep track of this one
# even if fixing HEAD may be complicated
class Ruleset(models.Model, Transformable):
    name = models.CharField(max_length=100, unique=True)
    descr = models.CharField(max_length=400, blank=True)
    created_date = models.DateTimeField("date created")
    updated_date = models.DateTimeField("date updated", blank=True)
    validity = models.BooleanField(default=True)
    errors = models.TextField(blank=True)
    rules_count = models.IntegerField(default=0)
    suppressed_sids = models.TextField(verbose_name="Suppress events", default="", blank=True)
    activate_categories = models.BooleanField(default=True)

    editable = True

    # List of Source that can be used in the ruleset
    # It can be a specific version or HEAD if we want to use
    # latest available
    sources = models.ManyToManyField(Source)
    # List of Category selected in the ruleset
    categories = models.ManyToManyField(Category, blank=True)
    rules_transformation = models.ManyToManyField(
        Rule, through="RuleTransformation", related_name="rules_transformed", blank=True
    )
    categories_transformation = models.ManyToManyField(
        Category, through="CategoryTransformation", related_name="categories_transformed", blank=True
    )

    # List or Rules to suppressed from the Ruleset
    # Exported as suppression list in oinkmaster

    # Operations
    # Creation:
    #  - define sources
    #  - define version
    #  - define categories
    #  - define suppressed rules
    # Delete
    # Copy
    #  - Specify new name
    # Refresh:
    #  - trigger update of sources
    #  - build new head
    # Update:
    #  - define version
    #  - update link
    # Generate appliance ruleset to directory:
    #  - get files from correct version exported to directory
    # Apply ruleset:
    #  - Tell Ansible to publish

    def __str__(self):
        return self.name

    def _json_errors(self):
        return json.loads(self.errors)

    json_errors = property(_json_errors)

    def get_processing_filter_thresholds(self):
        for f in self.processing_filters.filter(enabled=True, action="threshold"):
            for item in f.get_threshold_content(self):
                yield item

    def get_user_actions(self, rversion_from, rversion_to, actions_type):
        ua_objects_from = rversion_from.ua_objects.filter(user_action__action_type__in=actions_type)
        ua_objects_to = rversion_to.ua_objects.filter(user_action__action_type__in=actions_type)

        user_action_pk_min = (
            ua_objects_from.filter(user_action__action_type__in=actions_type)
            .aggregate(models.Min("user_action__pk"))
            .get("user_action__pk__min")
        )

        user_action_pk_max = (
            ua_objects_to.filter(user_action__action_type__in=actions_type)
            .aggregate(models.Max("user_action__pk"))
            .get("user_action__pk__max")
        )

        user_has_all_ua = (
            ua_objects_from.values("user_action").count() == rversion_from.ua_objects.values("user_action").count()
        ) and (ua_objects_to.values("user_action").count() == rversion_to.ua_objects.values("user_action").count())

        qs = UserAction.objects.none()
        if user_action_pk_min is not None and user_action_pk_max is not None:
            qs = UserAction.objects.filter(
                pk__gte=user_action_pk_min,
                pk__lte=user_action_pk_max,
                action_type__in=actions_type,
                user_action_objects__action_key="ruleset",
                user_action_objects__object_id=self.pk,
            ).order_by("-date")
        return qs, user_has_all_ua

    @staticmethod
    def get_transformation_choices(key=Transformation.ACTION):
        # Keys
        ACTION = Transformation.ACTION
        LATERAL = Transformation.LATERAL
        TARGET = Transformation.TARGET

        allowed_choices = []

        if key == ACTION:
            all_choices_set = set(Transformation.ActionTransfoType.get_choices())
            allowed_choices = list(all_choices_set.intersection(set(settings.RULESET_TRANSFORMATIONS)))

            A_BYPASS = Transformation.A_BYPASS
            A_NONE = Transformation.A_NONE

            # TODO: move me in settings.RULESET_TRANSFORMATIONS
            allowed_choices.append((A_BYPASS.value, A_BYPASS.name.title()))
            allowed_choices.append((A_NONE.value, A_NONE.name.title()))

        if key == TARGET:
            CAT_DEFAULT = Transformation.T_CAT_DEFAULT
            RULESET_DEFAULT = Transformation.T_RULESET_DEFAULT

            allowed_choices = list(Transformation.TargetTransfoType.get_choices())
            allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace("_", " ").title()))
            allowed_choices.remove((RULESET_DEFAULT.value, RULESET_DEFAULT.name.replace("_", " ").title()))

        if key == LATERAL:
            CAT_DEFAULT = Transformation.L_CAT_DEFAULT
            RULESET_DEFAULT = Transformation.L_RULESET_DEFAULT

            allowed_choices = list(Transformation.LateralTransfoType.get_choices())
            allowed_choices.remove((CAT_DEFAULT.value, CAT_DEFAULT.name.replace("_", " ").title()))
            allowed_choices.remove((RULESET_DEFAULT.value, RULESET_DEFAULT.name.replace("_", " ").title()))

        return tuple(allowed_choices)

    @staticmethod
    def get_icon():
        return "fa-th"

    def remove_transformation(self, key):
        RulesetTransformation.objects.filter(ruleset_transformation=self, key=key.value).delete()

        self.save()

    def set_transformation(self, key=Transformation.ACTION, value=Transformation.A_DROP):
        self.remove_transformation(key)

        r = RulesetTransformation(ruleset_transformation=self, key=key.value, value=value.value)
        r.save()

        self.save()

    def get_transformed_categories(self, key=Transformation.ACTION, value=Transformation.A_DROP):
        # All transformed categories from this ruleset
        if key is None:
            return Category.objects.filter(categorytransformation__ruleset=self)

        return Category.objects.filter(
            categorytransformation__ruleset=self,
            categorytransformation__key=key.value,
            categorytransformation__value=value.value,
        )

    def get_transformed_rules(self, key=Transformation.ACTION, value=Transformation.A_DROP):
        # All transformed rules from this ruleset
        if key is None:
            return Rule.objects.filter(ruletransformation__ruleset=self)

        return Rule.objects.filter(
            ruletransformation__ruleset=self, ruletransformation__key=key.value, ruletransformation__value=value.value
        )

    def get_transformation(self, key=Transformation.ACTION):
        NONE = None
        TYPE = None

        if key == Transformation.ACTION:
            NONE = Transformation.A_NONE
            TYPE = Transformation.ActionTransfoType
        elif key == Transformation.LATERAL:
            NONE = Transformation.L_NO
            TYPE = Transformation.LateralTransfoType
        elif key == Transformation.TARGET:
            NONE = Transformation.T_NONE
            TYPE = Transformation.TargetTransfoType
        else:
            raise Exception("Key '%s' is unknown" % key)

        rt = RulesetTransformation.objects.filter(key=key.value, ruleset_transformation=self).exclude(value=NONE.value)

        if rt.count() > 0:
            return TYPE(rt[0].value)

        return None

    def is_transformed(self, key=Transformation.ACTION, value=Transformation.A_DROP):
        rulesets_t = Ruleset.objects.filter(
            rulesettransformation__key=key.value, rulesettransformation__value=value.value
        )

        return self.pk in rulesets_t.values_list("pk", flat=True)

    def get_absolute_url(self):
        return reverse("ruleset", args=[str(self.id)])

    def update(self):
        update_errors = []
        is_ti_url = False
        sources = self.sources.all()
        for source in sources:
            try:
                source.update()

                if source.method == "http" and source.is_ti_url() and not is_ti_url:
                    from scirius.utils import get_middleware_module

                    try:
                        get_middleware_module("common").data_export()
                        is_ti_url = True
                    except Exception as exc:
                        request_logger.error("Unable to export data: %s" % exc)
            except IOError as e:
                update_errors.append('Source "%s" update failed:\n\t%s' % (source.name, str(e)))

        # Update timestamp if at least one source update was successful
        if sources.count() != 0 and sources.count() != len(update_errors):
            self.updated_date = timezone.now()
            self.save()

        if len(update_errors):
            raise IOError(len(update_errors), "\n".join(update_errors))

    def generate(self, rules=False, version=None):
        filters = {
            "rule__category__source__in": self.sources.all(),
            "rule__category__in": self.categories.all(),
            "state": True,
        }
        if version is not None:
            filters.update({"version": version})

        ravs = (
            RuleAtVersion.objects.select_related("rule")
            .select_related("rule__category")
            .select_related("rule__category__source")
            .filter(**filters)
            .exclude(
                pk__in=SuppressedRuleAtVersion.objects.filter(ruleset=self)
                .values_list("rule_at_version__pk", flat=True)
                .distinct()
            )
            .order_by("rule__sid")
        )
        if rules is False:
            return ravs

        return (
            Rule.objects.filter(pk__in=ravs.values_list("rule__pk", flat=True))
            .annotate(
                untrusted=models.Case(
                    models.When(category__source__untrusted=False, then=False),
                    models.When(category__source__untrusted=True, then=True),
                    default=True,
                    output_field=models.BooleanField(),
                )
            )
            .order_by("sid")
        )

    def generate_threshold(self, directory):
        thresholdfile = os.path.join(directory, "threshold.config")
        with open(thresholdfile, "w") as f:
            f.writelines("%s\n" % (threshold) for threshold in Threshold.objects.filter(ruleset=self))

            f.writelines(self.get_processing_filter_thresholds())

            if self.suppressed_sids:
                f.write(self.suppressed_sids)

    def copy(self, name):
        orig_ruleset_pk = self.pk
        orig_sources = self.sources.all()
        orig_categories = self.categories.all()
        self.name = name
        self.pk = None
        self.id = None
        self.created_date = timezone.now()
        self.updated_date = self.created_date
        self.save()
        self.sources.set(orig_sources)
        self.categories.set(orig_categories)
        self.save()
        for truleset in RulesetTransformation.objects.filter(ruleset_transformation_id=orig_ruleset_pk):
            truleset.ruleset_transformation = self
            truleset.pk = None
            truleset.id = None
            truleset.save()
        for threshold in Threshold.objects.filter(ruleset_id=orig_ruleset_pk):
            threshold.ruleset = self
            threshold.pk = None
            threshold.id = None
            threshold.save()
        for tcat in CategoryTransformation.objects.filter(ruleset_id=orig_ruleset_pk):
            tcat.ruleset = self
            tcat.pk = None
            tcat.id = None
            tcat.save()
        for trule in RuleTransformation.objects.filter(ruleset_id=orig_ruleset_pk):
            trule.ruleset = self
            trule.pk = None
            trule.id = None
            trule.save()
        return self

    def export_files(self, directory):
        cats_content = ""
        iprep_content = ""
        for src in self.sources.all():
            cats, iprep = src.export_files(directory)
            if cats_content and cats:
                cats_content += "\n"
            cats_content += cats

            if iprep_content and iprep:
                iprep_content += "\n"
            iprep_content += iprep

        # generate threshold.config
        self.generate_threshold(directory)
        return cats_content, iprep_content

    def diff(self, mode="long"):
        sources = self.sources.all()
        sdiff = {}
        for source in sources:
            supdate = SourceUpdate.objects.filter(source=source).order_by("-created_date")
            if supdate.count() > 0:
                srcdiff = supdate[0].diff()
                if mode == "short":
                    num = 0
                    for key in srcdiff["stats"]:
                        num = num + srcdiff["stats"][key]
                    if num > 0:
                        sdiff[source.name] = srcdiff
                else:
                    sdiff[source.name] = srcdiff
        return sdiff

    def export(self):
        content = self.to_buffer()
        tar_path_io = BytesIO()
        try:
            with tarfile.open(fileobj=tar_path_io, mode="w:gz") as tar:
                file_info = tarfile.TarInfo("scirius.rules")
                file_info.size = len(content)
                tar.addfile(file_info, BytesIO(bytes(content, "utf-8")))
        except Exception as e:
            request_logger.warning("Ruleset export failed: %s" % e)

        return tar_path_io

    def to_buffer(self):
        from scirius.utils import get_middleware_module

        ravs = self.generate(version=0)
        self.number_of_rules(ravs.values("rule").distinct())

        # test is not done on stamus source
        sources = get_middleware_module("common").custom_source_datatype()
        ravs = ravs.exclude(rule__category__source__datatype__in=sources)
        file_content = "# Rules file for %s generated by Scirius at %s\n" % (self.name, str(timezone.now()))

        if ravs.count() > 0:
            try:
                Rule.enable_cache()

                rules_content = []
                for rav in ravs:
                    # All rules are at version = 0 while test
                    # is not done on stamus source
                    c = rav.generate_content(self)
                    if c:
                        rules_content.append(c)
                file_content += "\n".join(rules_content)
            finally:
                Rule.disable_cache()

        return file_content

    def number_of_rules(self, rules=None):
        if rules is None:
            rules = self.generate(version=0, rules=True)

        self.rules_count = rules.count()
        self.save()
        return {"rules_count": self.rules_count}

    def test_rule_buffer(self, rule_buffer, engine_analysis=False):
        testor = TestRules()
        related_files, cats_content, iprep_content = self.prepare_tests_files()

        return testor.check_rule_buffer(
            rule_buffer,
            related_files=related_files,
            cats_content=cats_content,
            iprep_content=iprep_content,
            engine_analysis=engine_analysis,
        )

    def prepare_tests_files(self):
        tmpdir = tempfile.mkdtemp()
        cats_content, iprep_content = self.export_files(tmpdir)
        related_files = {}

        for root, _, files in os.walk(tmpdir):
            for f in files:
                fullpath = os.path.join(root, f)
                with open(fullpath, "r") as cf:
                    related_files[f] = cf.read(50 * 1024)

        shutil.rmtree(tmpdir)
        return related_files, cats_content, iprep_content

    def analyse_rules(self):
        testor = TestRules()
        related_files, cats_content, iprep_content = self.prepare_tests_files()

        all_versions = RuleAtVersion.get_versions_to_analyse()
        for version in all_versions:
            for source in self.sources.all():
                contents = (
                    RuleAtVersion.objects.filter(
                        rule__category__source=source, updated_date__gte=source.updated_date, version=version
                    )
                    .distinct()
                    .values_list("content", flat=True)
                )

                if contents:
                    content = testor.rules_infos(
                        "\n".join(contents) + f"\n## SLS dataset-dir: {Source.DATASET_PATH}\n## SLS suricata-options: --set datasets.limits.single-hashsize=5000000",
                        related_files=related_files,
                        cats_content=cats_content,
                        iprep_content=iprep_content,
                    )
                    RuleAtVersion.write_analyse(content, version)

    def test(self):
        rule_buffer = self.to_buffer() + "\n## SLS suricata-options: --set datasets.limits.single-hashsize=5000000"
        result = self.test_rule_buffer(rule_buffer)
        result["rules_count"] = self.rules_count
        self.validity = result["status"]
        if "errors" in result:
            self.errors = json.dumps(result["errors"])
        else:
            self.errors = json.dumps([])
        self.save()
        return result

    def disable_rules_at_version(self, ravs):
        suppr_ravs = []
        for rav in ravs:
            if SuppressedRuleAtVersion.objects.filter(ruleset=self, rule_at_version=rav).count() == 0:
                suppr_ravs.append(SuppressedRuleAtVersion(ruleset=self, rule_at_version=rav))

        if len(suppr_ravs):
            SuppressedRuleAtVersion.objects.bulk_create(suppr_ravs)

    def enable_rules_at_version(self, ravs):
        restore_ravs = []
        for rav in ravs:
            if SuppressedRuleAtVersion.objects.filter(ruleset=self, rule_at_version=rav).count() > 0:
                restore_ravs.append(rav)

        if len(restore_ravs):
            SuppressedRuleAtVersion.objects.filter(rule_at_version__in=restore_ravs, ruleset=self).delete()

    @classmethod
    def create_ruleset(cls, name, sources=None, activate_categories=False):
        if sources is None:
            sources = []
        ruleset = cls.objects.create(
            name=name, created_date=timezone.now(), updated_date=timezone.now(), activate_categories=activate_categories
        )

        for src_pk in sources:
            src = Source.objects.get(pk=src_pk)
            ruleset.sources.add(src)
            if activate_categories:
                for cat in Category.objects.filter(source=src):
                    ruleset.categories.add(cat)

        return ruleset

    def get_single_policies(self) -> QuerySet:
        """
        Get policies (RuleProcessingFilter) that are only linked to this Ruleset.
        It is usefull when we need to delete a ruleset to avoid orphan policies.
        """
        return (
            RuleProcessingFilter.objects.annotate(models.Count("rulesets"))
            .filter(rulesets__pk=self.pk, rulesets__count=1)
            .order_by("event_type", "action")
        )

    @transaction.atomic
    def delete(self):
        """
        Delete ruleset and single policies (not linked to another ruleset).

        Also re-index policies to avoid gaps in indexes.
        """
        # delete single policies
        Ruleset.objects.get(pk=self.pk).get_single_policies().delete()
        # rebuild policy index
        counter = 0
        objs = []
        for policy in RuleProcessingFilter.objects.order_by("index").iterator():
            policy.index = counter
            objs.append(policy)
            counter += 1
        RuleProcessingFilter.objects.bulk_update(objs, ["index"])
        # finally, delete the ruleset
        super().delete()


class RuleTransformation(Transformation):
    ruleset = models.ForeignKey(Ruleset, on_delete=models.CASCADE)
    rule_transformation = models.ForeignKey(Rule, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("ruleset", "rule_transformation", "key")


class SuppressedRuleAtVersion(models.Model):
    ruleset = models.ForeignKey(Ruleset, on_delete=models.CASCADE)
    rule_at_version = models.ForeignKey(RuleAtVersion, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("ruleset", "rule_at_version")


class CategoryTransformation(Transformation):
    ruleset = models.ForeignKey(Ruleset, on_delete=models.CASCADE)
    category_transformation = models.ForeignKey(Category, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("ruleset", "category_transformation", "key")


class RulesetTransformation(Transformation):
    ruleset_transformation = models.ForeignKey(Ruleset, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("ruleset_transformation", "key")


class Threshold(models.Model):
    THRESHOLD_TYPES = (("threshold", "threshold"), ("suppress", "suppress"))
    THRESHOLD_TYPE_TYPES = (("limit", "limit"), ("threshold", "threshold"), ("both", "both"))
    TRACK_BY_CHOICES = (("by_src", "by_src"), ("by_dst", "by_dst"))
    descr = models.CharField(max_length=400, blank=True)
    threshold_type = models.CharField(max_length=20, choices=THRESHOLD_TYPES, default="suppress")
    type = models.CharField(max_length=20, choices=THRESHOLD_TYPE_TYPES, default="limit")
    gid = models.IntegerField(default=1)
    rule = models.ForeignKey(Rule, default=None, on_delete=models.CASCADE)
    ruleset = models.ForeignKey(Ruleset, default=None, on_delete=models.CASCADE)
    track_by = models.CharField(max_length=10, choices=TRACK_BY_CHOICES, default="by_src")
    net = models.CharField(max_length=100, blank=True, validators=[validate_addresses_or_networks])
    count = models.IntegerField(default=1)
    seconds = models.IntegerField(default=60)

    def __str__(self):
        rep = ""
        if self.threshold_type == "suppress":
            net = self.net
            if "," in self.net:
                net = "[%s]" % self.net

            rep = "suppress gen_id %d, sig_id %d" % (self.gid, self.rule.sid)
            rep += ", track %s, ip %s" % (self.track_by, net)
        else:
            rep = "%s gen_id %d, sig_id %d, type %s, track %s, count %d, seconds %d" % (
                self.threshold_type,
                self.gid,
                self.rule.sid,
                self.type,
                self.track_by,
                self.count,
                self.seconds,
            )
        return rep

    def get_absolute_url(self):
        return reverse("threshold", args=[str(self.id)])

    def contain(self, elt):
        if elt.threshold_type != self.threshold_type:
            return False

        if elt.track_by != self.track_by:
            return False

        if elt.threshold_type == "suppress":
            if not IPy.IP(self.net).overlaps(IPy.IP(elt.net)):
                return False

        return True


def dependencies_check(obj):
    if obj == Source:
        return None

    if obj == Ruleset:
        if Source.objects.count() == 0:
            return "You need first to create and update a source."
        if Rule.objects.count() == 0:
            return "You need first to update existing source."
        return None

    if Source.objects.count() == 0:
        return "You need first to create a source and a ruleset."

    if Ruleset.objects.count() == 0:
        return "You need first to create a ruleset."
    return None


def export_iprep_files(target_dir, cats_content, iprep_content):
    group_rules = Rule.objects.filter(group=True).order_by("sid")
    cat_map = {}

    with open(target_dir + "/" + "scirius-categories.txt", "w") as rfile:
        index = 1
        for rule in group_rules:
            rfile.write("%s,%d,%s\n" % (index, rule.sid, rule.msg))
            cat_map[index] = rule
            index = index + 1
        if cats_content:
            rfile.write(cats_content)

    with open(target_dir + "/" + "scirius-iprep.list", "w") as rfile:
        for cate in cat_map:
            rfile.writelines("%s,%d,100\n" % (IP, cate) for IP in cat_map[cate].group_ips_list.split(","))
        if iprep_content:
            rfile.write(iprep_content)


class RuleProcessingFilter(models.Model):
    """
    Also called policy
    """

    action = models.CharField(max_length=10)
    options = models.CharField(max_length=512, null=True, blank=True)
    index = models.PositiveIntegerField()
    description = models.TextField(default="")
    enabled = models.BooleanField(default=True)
    rulesets = models.ManyToManyField(Ruleset, related_name="processing_filters")
    imported = models.BooleanField(default=False)
    event_type = models.CharField(max_length=32, default="alert", null=False, blank=False)

    class Meta:
        ordering: Iterable[str] = ["index"]

    def __str__(self):
        filters = [str(f) for f in self.filter_defs.order_by("key")]
        return "{} ({})".format(self.action, ", ".join(filters))

    def get_options(self):
        if not self.options:
            return {}
        return json.loads(self.options)

    def get_threshold_content(self, ruleset=None):
        sid_track_ip = {}
        sids = []
        try:
            sid = self.filter_defs.get(key="alert.signature_id").value
            sid_track_ip = {str(sid): []}
            sids.append(sid)
        except models.ObjectDoesNotExist:
            pass

        try:
            msg = self.filter_defs.get(key="msg").value
            sids = list(Rule.objects.filter(msg__icontains=msg).order_by("sid").values_list("sid", flat=True))
            sid_track_ip = {str(sid_): [] for sid_ in sids} if msg else None
        except models.ObjectDoesNotExist:
            pass

        try:
            content = self.filter_defs.get(key="content").value
            sids = list(Rule.objects.filter(content__icontains=content).order_by("sid").values_list("sid", flat=True))
            sid_track_ip = {str(sid_): [] for sid_ in sids} if content else None
        except models.ObjectDoesNotExist:
            pass

        try:
            msg = self.filter_defs.get(key="alert.signature").value
            sids = list(Rule.objects.filter(msg=msg).order_by("sid").values_list("sid", flat=True))
            sid_track_ip = {str(sid): [] for sid in sids} if msg else None
        except models.ObjectDoesNotExist:
            pass

        if self.action == "suppress":
            try:
                src_ip = self.filter_defs.get(key="src_ip")
            except models.ObjectDoesNotExist:
                src_ip = None

            try:
                dest_ip = self.filter_defs.get(key="dest_ip")
            except models.ObjectDoesNotExist:
                dest_ip = None

            try:
                alert_target_ip = self.filter_defs.get(key="alert.target.ip")
            except models.ObjectDoesNotExist:
                alert_target_ip = None

            try:
                alert_source_ip = self.filter_defs.get(key="alert.source.ip")
            except models.ObjectDoesNotExist:
                alert_source_ip = None

            if alert_source_ip or alert_target_ip:
                rules = Rule.objects.filter(sid__in=sids).annotate(
                    untrusted=models.Case(
                        models.When(category__source__untrusted=False, then=False),
                        models.When(category__source__untrusted=True, then=True),
                        default=True,
                        output_field=models.BooleanField(),
                    )
                )

                alert_ip = alert_source_ip if alert_source_ip is not None else alert_target_ip

                for rule in rules:
                    content = rule.generate_content(ruleset)

                    if "target:src_ip;" in content:
                        if alert_target_ip:
                            sid_track_ip[str(rule.sid)] = (
                                "by_src",
                                alert_ip.value,
                            )
                        elif alert_source_ip:
                            sid_track_ip[str(rule.sid)] = (
                                "by_dst",
                                alert_ip.value,
                            )
                    elif "target:dest_ip;" in content:
                        if alert_target_ip:
                            sid_track_ip[str(rule.sid)] = (
                                "by_dst",
                                alert_ip.value,
                            )
                        elif alert_source_ip:
                            sid_track_ip[str(rule.sid)] = (
                                "by_src",
                                alert_ip.value,
                            )
                    else:
                        sid_track_ip.pop(str(rule.sid), None)

            elif src_ip:
                for sid in sids:
                    sid_track_ip[str(sid)] = ("by_src", src_ip.value)
            else:
                for sid in sids:
                    sid_track_ip[str(sid)] = ("by_dst", dest_ip.value)

            res = []
            for sid, val in sorted(sid_track_ip.items()):
                if len(val):
                    res.append(f"suppress gen_id 1, sid_id {sid}, track {val[0]}, ip {val[1]}\n")
            return res

        if self.action == "threshold":
            options = self.get_options()

            res = []
            for sid in sid_track_ip:
                res.append(
                    "threshold gen_id 1, sig_id {}, type {}, track {}, count {}, seconds {}\n".format(
                        sid, options["type"], options["track"], options["count"], options["seconds"]
                    )
                )
            return res

        raise Exception(f"Invalid processing filter action {self.action}")

    @staticmethod
    def get_icon():
        return "pficon-filter"


class RuleProcessingFilterDef(models.Model):
    OPERATOR = (("equal", "Equal"), ("different", "Different"), ("contains", "Contains"))
    OPERATOR_DISPLAY: ClassVar[dict[str, str]] = {"equal": "=", "different": "!="}

    key = models.CharField(max_length=512)
    value = models.CharField(max_length=1024)
    operator = models.CharField(max_length=10, choices=OPERATOR)
    proc_filter = models.ForeignKey(RuleProcessingFilter, on_delete=models.CASCADE, related_name="filter_defs")
    full_string = models.BooleanField(default=True)

    class Meta:
        ordering = ("key", "value")

    def __str__(self) -> str:
        op = self.OPERATOR_DISPLAY.get(self.operator, self.operator)
        return f"{self.key} {op} {self.value}"
