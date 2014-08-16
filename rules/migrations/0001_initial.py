# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Source'
        db.create_table(u'rules_source', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=100)),
            ('created_date', self.gf('django.db.models.fields.DateTimeField')()),
            ('updated_date', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
            ('uri', self.gf('django.db.models.fields.CharField')(max_length=400)),
            ('method', self.gf('django.db.models.fields.CharField')(max_length=10)),
            ('datatype', self.gf('django.db.models.fields.CharField')(max_length=10)),
        ))
        db.send_create_signal(u'rules', ['Source'])

        # Adding model 'SourceAtVersion'
        db.create_table(u'rules_sourceatversion', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('source', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['rules.Source'])),
            ('version', self.gf('django.db.models.fields.CharField')(max_length=42)),
            ('git_version', self.gf('django.db.models.fields.CharField')(default='HEAD', max_length=42)),
            ('updated_date', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime(2014, 2, 12, 0, 0), blank=True)),
        ))
        db.send_create_signal(u'rules', ['SourceAtVersion'])

        # Adding model 'Category'
        db.create_table(u'rules_category', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=100)),
            ('filename', self.gf('django.db.models.fields.CharField')(max_length=200)),
            ('descr', self.gf('django.db.models.fields.CharField')(max_length=400, blank=True)),
            ('created_date', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime(2014, 2, 12, 0, 0))),
            ('source', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['rules.Source'])),
        ))
        db.send_create_signal(u'rules', ['Category'])

        # Adding model 'Reference'
        db.create_table(u'rules_reference', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('key', self.gf('django.db.models.fields.CharField')(max_length=100)),
            ('value', self.gf('django.db.models.fields.CharField')(max_length=100)),
        ))
        db.send_create_signal(u'rules', ['Reference'])

        # Adding model 'Rule'
        db.create_table(u'rules_rule', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('category', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['rules.Category'])),
            ('msg', self.gf('django.db.models.fields.CharField')(max_length=1000)),
            ('state', self.gf('django.db.models.fields.BooleanField')(default=True)),
            ('sid', self.gf('django.db.models.fields.IntegerField')(default=0, unique=True)),
            ('rev', self.gf('django.db.models.fields.IntegerField')(default=0)),
            ('content', self.gf('django.db.models.fields.CharField')(max_length=10000)),
        ))
        db.send_create_signal(u'rules', ['Rule'])

        # Adding M2M table for field references on 'Rule'
        db.create_table(u'rules_rule_references', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('rule', models.ForeignKey(orm[u'rules.rule'], null=False)),
            ('reference', models.ForeignKey(orm[u'rules.reference'], null=False))
        ))
        db.create_unique(u'rules_rule_references', ['rule_id', 'reference_id'])

        # Adding model 'Ruleset'
        db.create_table(u'rules_ruleset', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=100)),
            ('descr', self.gf('django.db.models.fields.CharField')(max_length=400, blank=True)),
            ('created_date', self.gf('django.db.models.fields.DateTimeField')()),
            ('updated_date', self.gf('django.db.models.fields.DateTimeField')(blank=True)),
        ))
        db.send_create_signal(u'rules', ['Ruleset'])

        # Adding M2M table for field sources on 'Ruleset'
        db.create_table(u'rules_ruleset_sources', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('ruleset', models.ForeignKey(orm[u'rules.ruleset'], null=False)),
            ('sourceatversion', models.ForeignKey(orm[u'rules.sourceatversion'], null=False))
        ))
        db.create_unique(u'rules_ruleset_sources', ['ruleset_id', 'sourceatversion_id'])

        # Adding M2M table for field categories on 'Ruleset'
        db.create_table(u'rules_ruleset_categories', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('ruleset', models.ForeignKey(orm[u'rules.ruleset'], null=False)),
            ('category', models.ForeignKey(orm[u'rules.category'], null=False))
        ))
        db.create_unique(u'rules_ruleset_categories', ['ruleset_id', 'category_id'])

        # Adding M2M table for field suppressed_rules on 'Ruleset'
        db.create_table(u'rules_ruleset_suppressed_rules', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('ruleset', models.ForeignKey(orm[u'rules.ruleset'], null=False)),
            ('rule', models.ForeignKey(orm[u'rules.rule'], null=False))
        ))
        db.create_unique(u'rules_ruleset_suppressed_rules', ['ruleset_id', 'rule_id'])


    def backwards(self, orm):
        # Deleting model 'Source'
        db.delete_table(u'rules_source')

        # Deleting model 'SourceAtVersion'
        db.delete_table(u'rules_sourceatversion')

        # Deleting model 'Category'
        db.delete_table(u'rules_category')

        # Deleting model 'Reference'
        db.delete_table(u'rules_reference')

        # Deleting model 'Rule'
        db.delete_table(u'rules_rule')

        # Removing M2M table for field references on 'Rule'
        db.delete_table('rules_rule_references')

        # Deleting model 'Ruleset'
        db.delete_table(u'rules_ruleset')

        # Removing M2M table for field sources on 'Ruleset'
        db.delete_table('rules_ruleset_sources')

        # Removing M2M table for field categories on 'Ruleset'
        db.delete_table('rules_ruleset_categories')

        # Removing M2M table for field suppressed_rules on 'Ruleset'
        db.delete_table('rules_ruleset_suppressed_rules')


    models = {
        u'rules.category': {
            'Meta': {'object_name': 'Category'},
            'created_date': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2014, 2, 12, 0, 0)'}),
            'descr': ('django.db.models.fields.CharField', [], {'max_length': '400', 'blank': 'True'}),
            'filename': ('django.db.models.fields.CharField', [], {'max_length': '200'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['rules.Source']"})
        },
        u'rules.reference': {
            'Meta': {'object_name': 'Reference'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'key': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'value': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        u'rules.rule': {
            'Meta': {'object_name': 'Rule'},
            'category': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['rules.Category']"}),
            'content': ('django.db.models.fields.CharField', [], {'max_length': '10000'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'msg': ('django.db.models.fields.CharField', [], {'max_length': '1000'}),
            'references': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['rules.Reference']", 'symmetrical': 'False', 'blank': 'True'}),
            'rev': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'sid': ('django.db.models.fields.IntegerField', [], {'default': '0', 'unique': 'True'}),
            'state': ('django.db.models.fields.BooleanField', [], {'default': 'True'})
        },
        u'rules.ruleset': {
            'Meta': {'object_name': 'Ruleset'},
            'categories': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['rules.Category']", 'symmetrical': 'False', 'blank': 'True'}),
            'created_date': ('django.db.models.fields.DateTimeField', [], {}),
            'descr': ('django.db.models.fields.CharField', [], {'max_length': '400', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'sources': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['rules.SourceAtVersion']", 'symmetrical': 'False'}),
            'suppressed_rules': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['rules.Rule']", 'symmetrical': 'False', 'blank': 'True'}),
            'updated_date': ('django.db.models.fields.DateTimeField', [], {'blank': 'True'})
        },
        u'rules.source': {
            'Meta': {'object_name': 'Source'},
            'created_date': ('django.db.models.fields.DateTimeField', [], {}),
            'datatype': ('django.db.models.fields.CharField', [], {'max_length': '10'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'method': ('django.db.models.fields.CharField', [], {'max_length': '10'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'updated_date': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'uri': ('django.db.models.fields.CharField', [], {'max_length': '400'})
        },
        u'rules.sourceatversion': {
            'Meta': {'object_name': 'SourceAtVersion'},
            'git_version': ('django.db.models.fields.CharField', [], {'default': "'HEAD'", 'max_length': '42'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['rules.Source']"}),
            'updated_date': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2014, 2, 12, 0, 0)', 'blank': 'True'}),
            'version': ('django.db.models.fields.CharField', [], {'max_length': '42'})
        }
    }

    complete_apps = ['rules']