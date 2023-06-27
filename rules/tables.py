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


from django.template.defaultfilters import filesizeformat
from django.utils.html import format_html
from django.db.models import Max
from django.urls import reverse
from scirius.utils import SciriusTable
from rules.models import Ruleset, Category, Rule, Source, SourceUpdate, Threshold, UserAction
import django_tables2 as tables


class DefaultMeta:
    attrs = {"class": "paleblue"}


class RuleTable(SciriusTable):
    sid = tables.LinkColumn('rule', args=[tables.A('pk')])
    updated_date = tables.DateTimeColumn(format='%m/%d/%Y %I:%M %p')

    class Meta(DefaultMeta):
        model = Rule
        fields = ("sid", "msg", "updated_date")

    def render_updated_date(self, record):
        return record.ruleatversion_set.annotate(
            Max('updated_date')
        ).first().updated_date__max.strftime('%m/%d/%Y %I:%M %p')

    def order_updated_date(self, queryset, is_descending):
        return (queryset.annotate(
            updated_date=Max('ruleatversion__updated_date')
        ).order_by(
            '%s%s' % ('-' if is_descending else '', 'updated_date')
        ), True)


class ExtendedRuleTable(SciriusTable):
    sid = tables.Column()

    class Meta(DefaultMeta):
        model = Rule
        fields = ("sid", "msg", "category", "hits")
        orderable = False

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request')
        super().__init__(*args, **kwargs)

    def render_sid(self, record):
        if self.request.user.has_perm('rules.ruleset_policy_view'):
            return format_html('<a href="{}">{}</a>', reverse('rule', args=[record.pk]), record.pk)
        return record.pk


class UpdateRuleTable(SciriusTable):
    sid = tables.LinkColumn('rule', args=[tables.A('pk')])

    class Meta(DefaultMeta):
        model = Rule
        fields = ("sid", "msg", "category")


class DeletedRuleTable(SciriusTable):

    class Meta(DefaultMeta):
        model = Rule
        fields = ("sid", "msg", "category")


class EditSourceTable(SciriusTable):
    source_selection = tables.CheckBoxColumn(
        accessor="pk",
        attrs={"th__input": {"onclick": "tables2_toggle(this, 'source_selection')"}},
        orderable=False
    )
    name = tables.LinkColumn('source', args=[tables.A('pk')])

    class Meta(DefaultMeta):
        model = Source
        fields = ("source_selection", "name")

    def order_name(self, queryset, is_descending):
        return (queryset.order_by('%s%s' % ('-' if is_descending else '', 'name')), True)


class CategoryTable(SciriusTable):
    name = tables.LinkColumn('category', args=[tables.A('pk')])

    class Meta(DefaultMeta):
        model = Category
        fields = ("name", "descr", "created_date")


class EditCategoryTable(SciriusTable):
    category_selection = tables.CheckBoxColumn(
        accessor="pk",
        attrs={"th__input": {"onclick": "tables2_toggle(this, 'category_selection')"}},
        orderable=False
    )
    name = tables.LinkColumn('category', args=[tables.A('pk')])

    class Meta(DefaultMeta):
        model = Category
        fields = ("category_selection", "name", "descr", "created_date")


class EditRuleTable(SciriusTable):
    rule_selection = tables.CheckBoxColumn(
        accessor="pk",
        attrs={"th__input": {"onclick": "tables2_toggle(this, 'rule_selection')"}},
        orderable=False
    )
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
        attrs = {'id': 'rulesets', 'class': 'paleblue'}


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


class RuleStatsTable(SciriusTable):
    host = tables.Column()
    count = tables.Column()

    class Meta(DefaultMeta):
        fields = ("host", "count")


class RuleHostTable(SciriusTable):
    host = tables.Column()
    count = tables.Column()
    actions = tables.Column()

    class Meta(DefaultMeta):
        fields = ("host", "count", "actions")
        attrs = {'id': 'hosts', 'class': 'paleblue'}


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
    pk = tables.LinkColumn('threshold', args=[tables.A('pk')])
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
