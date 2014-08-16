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

from django.conf.urls import patterns, url

from rules import views

urlpatterns = patterns('',
    url(r'^$', views.index, name='index'),
    url(r'^about/$', views.about, name='about'),
    url(r'^source/$', views.sources, name='sources'),
    url(r'^source/add$', views.add_source, name='add_source'),
    url(r'^source/(?P<source_id>\d+)/$', views.source, name='source'),
    url(r'^source/(?P<source_id>\d+)/update$', views.update_source, name='update_source'),
    url(r'^source/(?P<source_id>\d+)/diff$', views.diff_source, name='diff_source'),
    url(r'^source/(?P<source_id>\d+)/changelog', views.changelog_source, name='changelog_source'),
    url(r'^source/(?P<source_id>\d+)/edit$', views.edit_source, name='edit_source'),
    url(r'^source/(?P<source_id>\d+)/delete$', views.delete_source, name='delete_source'),
    url(r'^sourceupdate/(?P<update_id>\d+)$', views.sourceupdate, name='sourceupdate'),
    url(r'^category/$', views.categories, name='categories'),
    url(r'^category/(?P<cat_id>\d+)/$', views.category, name='category'),
    url(r'^ruleset/$', views.rulesets, name='rulesets'),
    url(r'^ruleset/add$', views.add_ruleset, name='rulesets'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/$', views.ruleset, name='ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/update$', views.update_ruleset, name='update_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/edit$', views.edit_ruleset, name='edit_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/delete$', views.delete_ruleset, name='delete_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/addsupprule$', views.ruleset_add_supprule, name='addsupprule'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/display$', views.ruleset, {'mode': 'display'}, name='display_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/export$', views.ruleset, {'mode': 'export'}, name='export_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/copy$', views.copy_ruleset, name='copy_ruleset'),
    url(r'^ruleset/(?P<ruleset_id>\d+)/changelog', views.changelog_ruleset, name='changelog_ruleset'),
    url(r'^rule/(?P<rule_id>\d+)/suppress$', views.suppress_rule, name='suppress_rule'),
    url(r'^rule/pk/(?P<rule_id>\d+)/$', views.rule, {'key': 'pk'}, name='rule'),
    url(r'^rule/(?P<rule_id>\d+)/$', views.rule, {'key': 'sid'}, name='rule_sid'),
)
