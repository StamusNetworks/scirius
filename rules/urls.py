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

from rules import views

urlpatterns = [
    path('', views.index, name='rules_index'),
    path('search/', views.search, name='scirius_search'),
    path('es/', views.elasticsearch, name='elasticsearch'),
    path('settings/', views.system_settings, name='system_settings'),
    path('source/', views.sources, name='sources'),
    path('source/add/', views.add_source, name='add_source'),
    path('source/add_public/', views.add_public_source, name='add_public_source'),
    path('source/update_public/', views.update_public_sources, name='update_public_sources'),
    path('source/<int:source_id>/', views.source, name='source'),
    path('source/<int:source_id>/update/', views.update_source, name='update_source'),
    path('source/<int:source_id>/changelog/', views.changelog_source, name='changelog_source'),
    path('source/<int:source_id>/edit/', views.edit_source, name='edit_source'),
    path('source/<int:source_id>/delete/', views.delete_source, name='delete_source'),
    path('source/<int:source_id>/activate/<int:ruleset_id>/', views.activate_source, name='activate_source'),
    path('sourceupdate/<int:update_id>/', views.sourceupdate, name='sourceupdate'),
    path('category/', views.categories, name='categories'),
    path('category/<int:cat_id>/', views.category, name='category'),
    path('category/<int:cat_id>/disable/', views.disable_category, name='disable_category'),
    path('category/<int:cat_id>/enable/', views.enable_category, name='enable_category'),
    path('category/<int:cat_id>/transform/', views.transform_category, name='transform_category'),
    path('ruleset/', views.rulesets, name='rulesets'),
    path('ruleset/add/', views.add_ruleset, name='add_ruleset'),
    path('ruleset/<int:ruleset_id>/', views.ruleset, name='ruleset'),
    path('ruleset/<int:ruleset_id>/update/', views.update_ruleset, name='update_ruleset'),
    path('ruleset/<int:ruleset_id>/edit/', views.edit_ruleset, name='edit_ruleset'),
    path('ruleset/<int:ruleset_id>/delete/', views.delete_ruleset, name='delete_ruleset'),
    path('ruleset/<int:ruleset_id>/addsupprule/', views.ruleset_add_supprule, name='addsupprule'),
    path('ruleset/<int:ruleset_id>/display/', views.ruleset, {'mode': 'display'}, name='display_ruleset'),
    path('ruleset/<int:ruleset_id>/export/', views.ruleset_export, name='export_ruleset'),
    path('ruleset/<int:ruleset_id>/copy/', views.copy_ruleset, name='copy_ruleset'),
    path('ruleset/<int:ruleset_id>/changelog/', views.changelog_ruleset, name='changelog_ruleset'),
    path('ruleset/<int:ruleset_id>/test/', views.test_ruleset, name='test_ruleset'),
    path('rule/<int:rule_id>/disable/', views.disable_rule, name='disable_rule'),
    path('rule/<int:rule_id>/enable/', views.enable_rule, name='enable_rule'),
    path('rule/<int:rule_id>/delete/', views.delete_alerts, name='delete_alerts'),
    path('rule_at_version/<int:rav_id>/availability/', views.rav_toggle_availability, name='rav_toggle_availability'),
    path('rule/<int:rule_id>/availability/', views.rule_toggle_availability, name='rule_toggle_availability'),
    path('rule/<int:rule_id>/edit/', views.edit_rule, name='edit_rule'),
    path('rule/<int:rule_id>/threshold/', views.threshold_rule, name='threshold_rule'),
    path('rule/<int:rule_id>/comment/', views.comment_rule, name='comment_rule'),
    path('rule/pk/<int:rule_id>/', views.rule, name='rule'),
    path('rule/<int:rule_id>/', views.rule, name='rule_sid'),
    path('rule/pk/<int:rule_id>/test/<int:ruleset_id>/', views.test_rule, name='test_rule'),
    path('info/', views.info, name='info'),
    path('threshold/<int:threshold_id>/', views.threshold, name='threshold'),
    path('threshold/<int:threshold_id>/delete/', views.delete_threshold, name='delete_threshold'),
    path('threshold/<int:threshold_id>/edit/', views.edit_threshold, name='edit_threshold'),
    path('history/', views.history, name='history'),
    path('comment/', views.history, name='comment'),
    path('policies/', views.policies, name='policies'),

    path('status/', views.status, name='status'),
    path('stasks/', views.stasks, name='view_stasks'),
    re_path(r'^task/(?P<task_id>[\w-]+)/$', views.task, name='view_task'),
    re_path(r'^task/(?P<task_id>[\w-]+)/revoke/$', views.revoke_task, name='revoke_task'),
    re_path(r'^scheduledtask/(?P<task_id>[\w-]+)/$', views.scheduledtask, name='scheduledtask'),
    re_path(r'^scheduledtask/(?P<task_id>[\w-]+)/delete/$', views.delete_scheduledtask, name='delete_scheduledtask'),
    re_path(r'^scheduledtask/(?P<task_id>[\w-]+)/edit/$', views.edit_scheduledtask, name='edit_scheduledtask'),
]
