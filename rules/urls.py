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

from __future__ import unicode_literals
from django.conf.urls import url

from rules import views

urlpatterns = [
    url(r'^$', views.index, name='rules_index'),
    url(r'^about/$', views.about, name='scirius_about'),
    url(r'^search$', views.search, name='scirius_search'),
    url(r'^es$', views.elasticsearch, name='elasticsearch'),
    url(r'^settings/$', views.system_settings, name='system_settings'),
    url(r'^source/$', views.sources, name='sources'),
    url(r'^source/add$', views.add_source, name='add_source'),
    url(r'^source/add_public$', views.add_public_source, name='add_public_source'),
    url(r'^source/update_public$', views.update_public_sources, name='update_public_sources'),
    url(r'^source/(?P<source_id>\d+)/$', views.source, name='source'),
    url(r'^source/(?P<source_id>\d+)/update$', views.update_source, name='update_source'),
    url(r'^source/(?P<source_id>\d+)/diff$', views.diff_source, name='diff_source'),
    url(r'^source/(?P<source_id>\d+)/changelog', views.changelog_source, name='changelog_source'),
    url(r'^source/(?P<source_id>\d+)/edit$', views.edit_source, name='edit_source'),
    url(r'^source/(?P<source_id>\d+)/delete$', views.delete_source, name='delete_source'),
    url(r'^source/(?P<source_id>\d+)/activate/(?P<ruleset_id>\d+)$', views. activate_source, name='activate_source'),
    url(r'^source/(?P<source_id>\d+)/test$', views.test_source, name='test_source'),
    url(r'^sourceupdate/(?P<update_id>\d+)$', views.sourceupdate, name='sourceupdate'),
    url(r'^category/$', views.categories, name='categories'),
    url(r'^category/(?P<cat_id>\d+)/$', views.category, name='category'),
    url(r'^category/(?P<cat_id>\d+)/disable$', views.disable_category, name='disable_category'),
    url(r'^category/(?P<cat_id>\d+)/enable$', views.enable_category, name='enable_category'),
    url(r'^category/(?P<cat_id>\d+)/transform$', views.transform_category, name='transform_category'),
    url(r'^ruleset/$', views.rulesets, name='rulesets'),
    url(r'^ruleset/add$', views.add_ruleset, name='add_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/$', views.ruleset, name='ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/update$', views.update_ruleset, name='update_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/edit$', views.edit_ruleset, name='edit_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/delete$', views.delete_ruleset, name='delete_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/addsupprule$', views.ruleset_add_supprule, name='addsupprule'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/display$', views.ruleset, {'mode': 'display'}, name='display_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/export$', views.ruleset, {'mode': 'export'}, name='export_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/copy$', views.copy_ruleset, name='copy_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/changelog', views.changelog_ruleset, name='changelog_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/test', views.test_ruleset, name='test_ruleset'),
    url(r'^rule/(?P<rule_id>\d+)/disable$', views.disable_rule, name='disable_rule'),
    url(r'^rule/(?P<rule_id>\d+)/enable$', views.enable_rule, name='enable_rule'),
    url(r'^rule/(?P<rule_id>\d+)/delete$', views.delete_alerts, name='delete_alerts'),
    url(r'^rule/(?P<rule_id>\d+)/availability$', views.toggle_availability, name='toggle_availability'),
    url(r'^rule/(?P<rule_id>\d+)/edit$', views.edit_rule, name='edit_rule'),
    url(r'^rule/(?P<rule_id>\d+)/threshold$', views.threshold_rule, name='threshold_rule'),
    url(r'^rule/(?P<rule_id>\d+)/comment$', views.comment_rule, name='comment_rule'),
    url(r'^rule/pk/(?P<rule_id>\d+)/$', views.rule, {'key': 'pk'}, name='rule'),
    url(r'^rule/(?P<rule_id>\d+)/$', views.rule, {'key': 'sid'}, name='rule_sid'),
    url(r'^rule/pk/(?P<rule_id>\d+)/test/(?P<ruleset_id>\d+)$', views.test_rule, {'key': 'pk'}, name='test_rule'),
    url(r'^info$', views.info, name='info'),
    url(r'^threshold/(?P<threshold_id>\d+)/$', views.threshold, name='threshold'),
    url(r'^threshold/(?P<threshold_id>\d+)/delete$', views.delete_threshold, name='delete_threshold'),
    url(r'^threshold/(?P<threshold_id>\d+)/edit$', views.edit_threshold, name='edit_threshold'),
    url(r'^history$', views.history, name='history'),
    url(r'^comment$', views.history, name='comment'),
    url(r'^comment/(?P<comment_id>\d+)/delete$', views.delete_comment, name='delete_comment'),
    url(r'^hunt$', views.hunt, name='hunt'),
    url(r'^humio$', views.humio, name='humio'),
]
