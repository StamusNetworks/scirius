# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Deleting field 'Rule.state_in_state'
        db.delete_column('rules_rule', 'state_in_state')

        # Adding field 'Rule.state_in_source'
        db.add_column('rules_rule', 'state_in_source',
                      self.gf('django.db.models.fields.BooleanField')(default=True),
                      keep_default=False)


    def backwards(self, orm):
        # Adding field 'Rule.state_in_state'
        db.add_column('rules_rule', 'state_in_state',
                      self.gf('django.db.models.fields.BooleanField')(default=True),
                      keep_default=False)

        # Deleting field 'Rule.state_in_source'
        db.delete_column('rules_rule', 'state_in_source')


    models = {
        'rules.category': {
            'Meta': {'object_name': 'Category'},
            'created_date': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'descr': ('django.db.models.fields.CharField', [], {'max_length': '400', 'blank': 'True'}),
            'filename': ('django.db.models.fields.CharField', [], {'max_length': '200'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['rules.Source']"})
        },
        'rules.flowbit': {
            'Meta': {'object_name': 'Flowbit'},
            'enable': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'isset': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'set': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['rules.Source']"})
        },
        'rules.rule': {
            'Meta': {'object_name': 'Rule'},
            'category': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['rules.Category']"}),
            'content': ('django.db.models.fields.CharField', [], {'max_length': '10000'}),
            'flowbits': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['rules.Flowbit']", 'symmetrical': 'False'}),
            'msg': ('django.db.models.fields.CharField', [], {'max_length': '1000'}),
            'rev': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'sid': ('django.db.models.fields.IntegerField', [], {'primary_key': 'True'}),
            'state': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'state_in_source': ('django.db.models.fields.BooleanField', [], {'default': 'True'})
        },
        'rules.ruleset': {
            'Meta': {'object_name': 'Ruleset'},
            'categories': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['rules.Category']", 'symmetrical': 'False', 'blank': 'True'}),
            'created_date': ('django.db.models.fields.DateTimeField', [], {}),
            'descr': ('django.db.models.fields.CharField', [], {'max_length': '400', 'blank': 'True'}),
            'errors': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'need_test': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'rules_count': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'sources': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['rules.SourceAtVersion']", 'symmetrical': 'False'}),
            'suppressed_rules': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['rules.Rule']", 'symmetrical': 'False', 'blank': 'True'}),
            'updated_date': ('django.db.models.fields.DateTimeField', [], {'blank': 'True'}),
            'validity': ('django.db.models.fields.BooleanField', [], {'default': 'True'})
        },
        'rules.source': {
            'Meta': {'object_name': 'Source'},
            'authkey': ('django.db.models.fields.CharField', [], {'max_length': '400', 'null': 'True', 'blank': 'True'}),
            'created_date': ('django.db.models.fields.DateTimeField', [], {}),
            'datatype': ('django.db.models.fields.CharField', [], {'max_length': '10'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'method': ('django.db.models.fields.CharField', [], {'max_length': '10'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'updated_date': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'uri': ('django.db.models.fields.CharField', [], {'max_length': '400', 'null': 'True', 'blank': 'True'})
        },
        'rules.sourceatversion': {
            'Meta': {'object_name': 'SourceAtVersion'},
            'git_version': ('django.db.models.fields.CharField', [], {'default': "'HEAD'", 'max_length': '42'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['rules.Source']"}),
            'updated_date': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'blank': 'True'}),
            'version': ('django.db.models.fields.CharField', [], {'max_length': '42'})
        },
        'rules.sourceupdate': {
            'Meta': {'object_name': 'SourceUpdate'},
            'changed': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'created_date': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'blank': 'True'}),
            'data': ('django.db.models.fields.TextField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['rules.Source']"}),
            'version': ('django.db.models.fields.CharField', [], {'max_length': '42'})
        },
        'rules.systemsettings': {
            'Meta': {'object_name': 'SystemSettings'},
            'http_proxy': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '200', 'blank': 'True'}),
            'https_proxy': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '200', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'use_elasticsearch': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'use_http_proxy': ('django.db.models.fields.BooleanField', [], {'default': 'False'})
        }
    }

    complete_apps = ['rules']