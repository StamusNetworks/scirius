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

from rules.models import Ruleset, Source, Category, Rule
import django_tables2 as tables

class DefaultMeta:
    attrs = {"class": "paleblue"}

class RuleTable(tables.Table):
    sid = tables.LinkColumn('rule', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Rule
        fields = ("sid", "msg")

class ExtendedRuleTable(tables.Table):
    sid = tables.LinkColumn('rule', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Rule
        fields = ("sid", "msg", "category", "hits")

class CategoryTable(tables.Table):
    name = tables.LinkColumn('category', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Category
        fields = ("name", "descr", "created_date")

class EditCategoryTable(tables.Table):
    category_selection = tables.CheckBoxColumn(accessor="pk", attrs = { "th__input":
                                        {"onclick": "tables2_toggle(this, 'category_selection')"},
                                        },
                                        orderable=False)
    name = tables.LinkColumn('category', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Category
        fields = ("category_selection", "name", "descr", "created_date")

class RuleTable(tables.Table):
    sid = tables.LinkColumn('rule', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Rule
        fields = ("sid", "msg")

class EditRuleTable(tables.Table):
    rule_selection = tables.CheckBoxColumn(accessor="pk", attrs = { "th__input":
                                        {"onclick": "tables2_toggle(this, 'rule_selection')"}},
                                        orderable=False)
    sid = tables.LinkColumn('rule', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Rule
        fields = ("rule_selection", "sid", "msg")

class RulesetTable(tables.Table):
    name = tables.LinkColumn('ruleset', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Ruleset
        fields = ("name", "created_date", "updated_date")

class SourceTable(tables.Table):
    name = tables.LinkColumn('source', args=[tables.A('pk')])
    class Meta(DefaultMeta):
        model = Source
        fields = ("name", "created_date", "updated_date")
