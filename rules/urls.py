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


from django.urls import re_path

from rules import views

urlpatterns = [
    re_path(r'^$', views.index, name='rules_index'),
    re_path(r'^search$', views.search, name='scirius_search'),
    re_path(r'^es$', views.elasticsearch, name='elasticsearch'),
    re_path(r'^settings/$', views.system_settings, name='system_settings'),
    re_path(r'^source/$', views.sources, name='sources'),
    re_path(r'^source/add$', views.add_source, name='add_source'),
    re_path(r'^source/add_public$', views.add_public_source, name='add_public_source'),
    re_path(r'^source/update_public$', views.update_public_sources, name='update_public_sources'),
    re_path(r'^source/(?P<source_id>\d+)/$', views.source, name='source'),
    re_path(r'^source/(?P<source_id>\d+)/update$', views.update_source, name='update_source'),
    re_path(r'^source/(?P<source_id>\d+)/diff$', views.diff_source, name='diff_source'),
    re_path(r'^source/(?P<source_id>\d+)/changelog', views.changelog_source, name='changelog_source'),
    re_path(r'^source/(?P<source_id>\d+)/edit$', views.edit_source, name='edit_source'),
    re_path(r'^source/(?P<source_id>\d+)/delete$', views.delete_source, name='delete_source'),
    re_path(r'^source/(?P<source_id>\d+)/activate/(?P<ruleset_id>\d+)$', views. activate_source, name='activate_source'),
    re_path(r'^source/(?P<source_id>\d+)/test$', views.test_source, name='test_source'),
    re_path(r'^sourceupdate/(?P<update_id>\d+)$', views.sourceupdate, name='sourceupdate'),
    re_path(r'^category/$', views.categories, name='categories'),
    re_path(r'^category/(?P<cat_id>\d+)/$', views.category, name='category'),
    re_path(r'^category/(?P<cat_id>\d+)/disable$', views.disable_category, name='disable_category'),
    re_path(r'^category/(?P<cat_id>\d+)/enable$', views.enable_category, name='enable_category'),
    re_path(r'^category/(?P<cat_id>\d+)/transform$', views.transform_category, name='transform_category'),
    re_path(r'^ruleset/$', views.rulesets, name='rulesets'),
    re_path(r'^ruleset/add$', views.add_ruleset, name='add_ruleset'),
    re_path(r'^ruleset/(?P<ruleset_id>\d+)/$', views.ruleset, name='ruleset'),
    re_path(r'^ruleset/(?P<ruleset_id>\d+)/update$', views.update_ruleset, name='update_ruleset'),
    re_path(r'^ruleset/(?P<ruleset_id>\d+)/edit$', views.edit_ruleset, name='edit_ruleset'),
    re_path(r'^ruleset/(?P<ruleset_id>\d+)/delete$', views.delete_ruleset, name='delete_ruleset'),
    re_path(r'^ruleset/(?P<ruleset_id>\d+)/addsupprule$', views.ruleset_add_supprule, name='addsupprule'),
    re_path(r'^ruleset/(?P<ruleset_id>\d+)/display$', views.ruleset, {'mode': 'display'}, name='display_ruleset'),
    re_path(r'^ruleset/(?P<ruleset_id>\d+)/export$', views.ruleset, {'mode': 'export'}, name='export_ruleset'),
    re_path(r'^ruleset/(?P<ruleset_id>\d+)/copy$', views.copy_ruleset, name='copy_ruleset'),
    re_path(r'^ruleset/(?P<ruleset_id>\d+)/changelog', views.changelog_ruleset, name='changelog_ruleset'),
    re_path(r'^ruleset/(?P<ruleset_id>\d+)/test', views.test_ruleset, name='test_ruleset'),
    re_path(r'^rule/(?P<rule_id>\d+)/disable$', views.disable_rule, name='disable_rule'),
    re_path(r'^rule/(?P<rule_id>\d+)/enable$', views.enable_rule, name='enable_rule'),
    re_path(r'^rule/(?P<rule_id>\d+)/delete$', views.delete_alerts, name='delete_alerts'),
    re_path(r'^rule/(?P<rule_id>\d+)/availability$', views.toggle_availability, name='toggle_availability'),
    re_path(r'^rule/(?P<rule_id>\d+)/edit$', views.edit_rule, name='edit_rule'),
    re_path(r'^rule/(?P<rule_id>\d+)/threshold$', views.threshold_rule, name='threshold_rule'),
    re_path(r'^rule/(?P<rule_id>\d+)/comment$', views.comment_rule, name='comment_rule'),
    re_path(r'^rule/pk/(?P<rule_id>\d+)/$', views.rule, {'key': 'pk'}, name='rule'),
    re_path(r'^rule/(?P<rule_id>\d+)/$', views.rule, {'key': 'sid'}, name='rule_sid'),
    re_path(r'^rule/pk/(?P<rule_id>\d+)/test/(?P<ruleset_id>\d+)$', views.test_rule, {'key': 'pk'}, name='test_rule'),
    re_path(r'^info$', views.info, name='info'),
    re_path(r'^threshold/(?P<threshold_id>\d+)/$', views.threshold, name='threshold'),
    re_path(r'^threshold/(?P<threshold_id>\d+)/delete$', views.delete_threshold, name='delete_threshold'),
    re_path(r'^threshold/(?P<threshold_id>\d+)/edit$', views.edit_threshold, name='edit_threshold'),
    re_path(r'^history$', views.history, name='history'),
    re_path(r'^comment$', views.history, name='comment'),
    re_path(r'^policies$', views.policies, name='policies'),
]
