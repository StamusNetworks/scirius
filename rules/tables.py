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

from __future__ import unicode_literals
from scirius.utils import SciriusTable, QueryBuilder
from django.template.defaultfilters import filesizeformat
from rules.models import Ruleset, Source, Category, Rule, SourceAtVersion, SourceUpdate, Threshold, UserAction
import django_tables2 as tables

class DefaultMeta:
    attrs = {"class": "paleblue"}

class JSTableMeta(DefaultMeta):
    template = "rules/django_tables2/js_sortable_table.html"

class JSTable(SciriusTable):
    update_callback = "null"

    def __init__(self, *args, **kwargs):
        super(JSTable, self).__init__(*args, **kwargs)
        self.source_query = QueryBuilder("/rules/es?query=:query:")


class RuleTable(SciriusTable):
    sid = tables.LinkColumn('rule', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Rule
        fields = ("sid", "msg", "updated_date")

class ExtendedRuleTable(JSTable):
    sid = tables.LinkColumn('rule', args=[tables.A('pk')])
    table_id = "#rules_table"

    class Meta(JSTableMeta):
        model = Rule
        fields = ("sid", "msg", "category", "hits")

class UpdateRuleTable(SciriusTable):
    sid = tables.LinkColumn('rule', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Rule
        fields = ("sid", "msg", "category")

class DeletedRuleTable(SciriusTable):
    class Meta(DefaultMeta):
        model = Rule
        fields = ("sid", "msg", "category")

class EditSourceAtVersionTable(SciriusTable):
    source_selection = tables.CheckBoxColumn(accessor="pk", attrs = { "th__input":
                                        {"onclick": "tables2_toggle(this, 'source_selection')"},
                                        },
                                        orderable=False)
    name = tables.LinkColumn('source', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = SourceAtVersion
        fields = ("source_selection", "name", "created_date")

class CategoryTable(SciriusTable):
    name = tables.LinkColumn('category', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Category
        fields = ("name", "descr", "created_date")

class EditCategoryTable(SciriusTable):
    category_selection = tables.CheckBoxColumn(accessor="pk", attrs = { "th__input":
                                        {"onclick": "tables2_toggle(this, 'category_selection')"},
                                        },
                                        orderable=False)
    name = tables.LinkColumn('category', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Category
        fields = ("category_selection", "name", "descr", "created_date")

class EditRuleTable(SciriusTable):
    rule_selection = tables.CheckBoxColumn(accessor="pk", attrs = { "th__input":
                                        {"onclick": "tables2_toggle(this, 'rule_selection')"}},
                                        orderable=False)
    sid = tables.LinkColumn('rule', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Rule
        fields = ("rule_selection", "sid", "msg")

class RulesetTable(SciriusTable):
    name = tables.LinkColumn('ruleset', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Ruleset
        fields = ("name", "created_date", "updated_date")

class SourceUpdateTable(SciriusTable):
    created_date = tables.LinkColumn('sourceupdate', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = SourceUpdate
        fields = ("created_date", "changed")

class StatusRulesetTable(SciriusTable):
    name = tables.LinkColumn('ruleset', args=[tables.A('pk')])
    status = tables.Column(verbose_name='Status in ruleset')
    threshold = tables.Column(verbose_name='Threshold')
    validity = tables.Column(verbose_name='Operational status')
    class Meta(DefaultMeta):
        fields = ("name", "status", "threshold", "validity")
        attrs = { 'id': 'rulesets', 'class': 'paleblue' }

class CategoryRulesetTable(SciriusTable):
    name = tables.LinkColumn('ruleset', args=[tables.A('pk')])
    status = tables.Column(verbose_name='Status in ruleset')
    action = tables.Column(verbose_name='Action Transformation')
    lateral = tables.Column(verbose_name='Lateral Transformation')
    target = tables.Column(verbose_name='Target Transformation')
    threshold = tables.Column(verbose_name='Threshold')

    class Meta(DefaultMeta):
        fields = ("name", "status", "action", "lateral", "target", "threshold")
        attrs = {'id': 'rulesets', 'class': 'paleblue'}
        order_by = ('name',)

class RuleStatsTable(JSTable):
    host = tables.Column()
    count = tables.Column()
    table_id = "#stats_table"

    class Meta(JSTableMeta):
        fields = ("host", "count")

class RuleHostTable(JSTable):
    host = tables.Column()
    count = tables.Column()
    actions = tables.Column()

    class Meta(JSTableMeta):
        fields = ("host", "count", "actions")
        attrs = { 'id': 'hosts', 'class': 'paleblue' }

class ESIndexessTable(SciriusTable):
    name = tables.Column()
    count = tables.Column()
    deleted = tables.Column()
    size = tables.Column()

    class Meta(DefaultMeta):
        fields = ("name", "count", "deleted", 'size')

    def render_size(self, value):
        return filesizeformat(value)

class ThresholdTable(SciriusTable):
    pk = tables.LinkColumn('threshold', args=[tables.A('pk')] )
    threshold_type = tables.Column("Type")
    net = tables.Column("Network")
    rule = tables.Column("Rule")
    ruleset = tables.Column("Ruleset")
    class Meta(DefaultMeta):
        model = Threshold
        exclude = ()

class RuleSuppressTable(SciriusTable):
    pk = tables.LinkColumn('threshold', args=[tables.A('pk')], verbose_name='ID')
    net = tables.Column("Network")
    ruleset = tables.Column("Ruleset")
    class Meta(DefaultMeta):
        model = Threshold
        fields = ("pk", "track_by", "net", "ruleset")

class RuleThresholdTable(SciriusTable):
    pk = tables.LinkColumn('threshold', args=[tables.A('pk')], verbose_name='ID')
    ruleset = tables.Column("Ruleset")
    class Meta(DefaultMeta):
        model = Threshold
        fields = ("pk", "track_by", "type", "count", "seconds", "ruleset")

class RulesetSuppressTable(SciriusTable):
    pk = tables.LinkColumn('threshold', args=[tables.A('pk')], verbose_name='ID')
    net = tables.Column("Network")
    class Meta(DefaultMeta):
        model = Threshold
        fields = ("pk", "rule", "track_by", "net")

class RulesetThresholdTable(SciriusTable):
    pk = tables.LinkColumn('threshold', args=[tables.A('pk')], verbose_name='ID')
    class Meta(DefaultMeta):
        model = Threshold
        fields = ("pk", "rule", "track_by", "type", "count", "seconds")

class HistoryTable(SciriusTable):
    class Meta(DefaultMeta):
        model = UserAction
        fields = ("username", "date", "action", "options", "userobject", "ruleset", "description", "comment")
