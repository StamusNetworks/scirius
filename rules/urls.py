"""
Copyright(C) 2014-2018, Stamus Networks
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

from django.urls import path
from django.urls import re_path

from rules.views.misc import index, search, elasticsearch, system_settings, info, history
from rules.views.source import (
    delete_ioc_metadata,
    sources,
    add_source,
    add_public_source,
    source,
    update_source,
    changelog_source,
    edit_source,
    delete_source,
    activate_source,
    sourceupdate,
    update_public_sources,
)
from rules.views.category import categories, category, transform_category, disable_category, enable_category
from rules.views.rule import (
    threshold,
    edit_threshold,
    delete_threshold,
    policies,
    rule,
    edit_rule,
    disable_rule,
    enable_rule,
    test_rule,
    delete_alerts,
    comment_rule,
    rule_toggle_availability,
    rav_toggle_availability,
    threshold_rule,
)
from rules.views.ruleset import (
    ruleset,
    rulesets,
    ruleset_export,
    add_ruleset,
    update_ruleset,
    changelog_ruleset,
    edit_ruleset,
    ruleset_add_supprule,
    copy_ruleset,
    delete_ruleset,
)
from rules.views.task import status, stasks, task, revoke_task, scheduledtask, delete_scheduledtask, edit_scheduledtask

urlpatterns = [
    path("", index, name="rules_index"),
    path("search/", search, name="scirius_search"),
    path("es/", elasticsearch, name="elasticsearch"),
    path("settings/", system_settings, name="system_settings"),
    path("source/", sources, name="sources"),
    path("source/add/", add_source, name="add_source"),
    path("source/add_public/", add_public_source, name="add_public_source"),
    path("source/update_public/", update_public_sources, name="update_public_sources"),
    path("source/<int:source_id>/", source, name="source"),
    path("source/<int:source_id>/update/", update_source, name="update_source"),
    path("source/<int:source_id>/changelog/", changelog_source, name="changelog_source"),
    path("source/<int:source_id>/edit/", edit_source, name="edit_source"),
    path("source/<int:source_id>/delete/", delete_source, name="delete_source"),
    path("source/<int:source_id>/activate/<int:ruleset_id>/", activate_source, name="activate_source"),
    path("sourceupdate/<int:update_id>/", sourceupdate, name="sourceupdate"),
    path("category/", categories, name="categories"),
    path("category/<int:cat_id>/", category, name="category"),
    path("category/<int:cat_id>/disable/", disable_category, name="disable_category"),
    path("category/<int:cat_id>/enable/", enable_category, name="enable_category"),
    path("category/<int:cat_id>/transform/", transform_category, name="transform_category"),
    path("ruleset/", rulesets, name="rulesets"),
    path("ruleset/add/", add_ruleset, name="add_ruleset"),
    path("ruleset/<int:ruleset_id>/", ruleset, name="ruleset"),
    path("ruleset/<int:ruleset_id>/update/", update_ruleset, name="update_ruleset"),
    path("ruleset/<int:ruleset_id>/edit/", edit_ruleset, name="edit_ruleset"),
    path("ruleset/<int:ruleset_id>/delete/", delete_ruleset, name="delete_ruleset"),
    path("ruleset/<int:ruleset_id>/addsupprule/", ruleset_add_supprule, name="addsupprule"),
    path("ruleset/<int:ruleset_id>/display/", ruleset, {"mode": "display"}, name="display_ruleset"),
    path("ruleset/<int:ruleset_id>/export/", ruleset_export, name="export_ruleset"),
    path("ruleset/<int:ruleset_id>/copy/", copy_ruleset, name="copy_ruleset"),
    path("ruleset/<int:ruleset_id>/changelog/", changelog_ruleset, name="changelog_ruleset"),
    path("rule/<int:rule_id>/disable/", disable_rule, name="disable_rule"),
    path("rule/<int:rule_id>/enable/", enable_rule, name="enable_rule"),
    path("rule/<int:rule_id>/delete/", delete_alerts, name="delete_alerts"),
    path("rule_at_version/<int:rav_id>/availability/", rav_toggle_availability, name="rav_toggle_availability"),
    path("rule/<int:rule_id>/availability/", rule_toggle_availability, name="rule_toggle_availability"),
    path("rule/<int:rule_id>/edit/", edit_rule, name="edit_rule"),
    path("rule/<int:rule_id>/threshold/", threshold_rule, name="threshold_rule"),
    path("rule/<int:rule_id>/comment/", comment_rule, name="comment_rule"),
    path("rule/pk/<int:rule_id>/", rule, name="rule"),
    path("rule/<int:rule_id>/", rule, name="rule_sid"),
    path("rule/pk/<int:rule_id>/test/<int:ruleset_id>/", test_rule, name="test_rule"),
    path("info/", info, name="info"),
    path("threshold/<int:threshold_id>/", threshold, name="threshold"),
    path("threshold/<int:threshold_id>/delete/", delete_threshold, name="delete_threshold"),
    path("threshold/<int:threshold_id>/edit/", edit_threshold, name="edit_threshold"),
    path("history/", history, name="history"),
    path("comment/", history, name="comment"),
    path("policies/", policies, name="policies"),
    path("ioc_metadata/<int:ioc_meta_id>/delete/", delete_ioc_metadata, name="delete_ioc_metadata"),
    path("status/", status, name="status"),
    path("stasks/", stasks, name="view_stasks"),
    re_path(r"^task/(?P<task_id>[\w-]+)/$", task, name="view_task"),
    re_path(r"^task/(?P<task_id>[\w-]+)/revoke/$", revoke_task, name="revoke_task"),
    re_path(r"^scheduledtask/(?P<task_id>[\w-]+)/$", scheduledtask, name="scheduledtask"),
    re_path(r"^scheduledtask/(?P<task_id>[\w-]+)/delete/$", delete_scheduledtask, name="delete_scheduledtask"),
    re_path(r"^scheduledtask/(?P<task_id>[\w-]+)/edit/$", edit_scheduledtask, name="edit_scheduledtask"),
]
