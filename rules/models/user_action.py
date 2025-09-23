from collections import OrderedDict
from copy import deepcopy
from typing import ClassVar, TypedDict

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils import timezone
from django.utils.html import format_html, format_html_join
from ipware.ip import get_client_ip

from rules.models.model import Rule, Source, RuleProcessingFilter


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

        html = format_html_join(
            "\n",
            '<div class="list-view-pf-additional-info-item"><span class="fa {}"></span>{}</div>',
            ((icon, klass_name) for icon, klass_name in icons),
        )

        return html

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
