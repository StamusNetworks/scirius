# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding field 'Suricata.output_directory'
        db.add_column('suricata_suricata', 'output_directory',
                      self.gf('django.db.models.fields.CharField')(default='/etc/suricata/rules/', max_length=400),
                      keep_default=False)


    def backwards(self, orm):
        # Deleting field 'Suricata.output_directory'
        db.delete_column('suricata_suricata', 'output_directory')


    models = {
        'rules.category': {
            'Meta': {'object_name': 'Category'},
            'created_date': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2014, 2, 17, 0, 0)'}),
            'descr': ('django.db.models.fields.CharField', [], {'max_length': '400', 'blank': 'True'}),
            'filename': ('django.db.models.fields.CharField', [], {'max_length': '200'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['rules.Source']"})
        },
        'rules.reference': {
            'Meta': {'object_name': 'Reference'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'key': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'value': ('django.db.models.fields.CharField', [], {'max_length': '1000'})
        },
        'rules.rule': {
            'Meta': {'object_name': 'Rule'},
            'category': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['rules.Category']"}),
            'content': ('django.db.models.fields.CharField', [], {'max_length': '10000'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'msg': ('django.db.models.fields.CharField', [], {'max_length': '1000'}),
            'references': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['rules.Reference']", 'symmetrical': 'False', 'blank': 'True'}),
            'rev': ('django.db.models.fields.IntegerField', [], {'default': '0'}),
            'sid': ('django.db.models.fields.IntegerField', [], {'default': '0', 'unique': 'True'}),
            'state': ('django.db.models.fields.BooleanField', [], {'default': 'True'})
        },
        'rules.ruleset': {
            'Meta': {'object_name': 'Ruleset'},
            'categories': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['rules.Category']", 'symmetrical': 'False', 'blank': 'True'}),
            'created_date': ('django.db.models.fields.DateTimeField', [], {}),
            'descr': ('django.db.models.fields.CharField', [], {'max_length': '400', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'sources': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['rules.SourceAtVersion']", 'symmetrical': 'False'}),
            'suppressed_rules': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['rules.Rule']", 'symmetrical': 'False', 'blank': 'True'}),
            'updated_date': ('django.db.models.fields.DateTimeField', [], {'blank': 'True'})
        },
        'rules.source': {
            'Meta': {'object_name': 'Source'},
            'created_date': ('django.db.models.fields.DateTimeField', [], {}),
            'datatype': ('django.db.models.fields.CharField', [], {'max_length': '10'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'method': ('django.db.models.fields.CharField', [], {'max_length': '10'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'updated_date': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'uri': ('django.db.models.fields.CharField', [], {'max_length': '400'})
        },
        'rules.sourceatversion': {
            'Meta': {'object_name': 'SourceAtVersion'},
            'git_version': ('django.db.models.fields.CharField', [], {'default': "'HEAD'", 'max_length': '42'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'source': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['rules.Source']"}),
            'updated_date': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2014, 2, 17, 0, 0)', 'blank': 'True'}),
            'version': ('django.db.models.fields.CharField', [], {'max_length': '42'})
        },
        'suricata.suricata': {
            'Meta': {'object_name': 'Suricata'},
            'created_date': ('django.db.models.fields.DateTimeField', [], {}),
            'descr': ('django.db.models.fields.CharField', [], {'max_length': '400'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '100'}),
            'output_directory': ('django.db.models.fields.CharField', [], {'max_length': '400'}),
            'ruleset': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['rules.Ruleset']", 'blank': 'True'}),
            'updated_date': ('django.db.models.fields.DateTimeField', [], {'blank': 'True'})
        }
    }

    complete_apps = ['suricata']