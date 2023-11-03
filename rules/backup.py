"""
Copyright(C) 2016, Stamus Networks
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


from django.conf import settings
import tarfile
import tempfile
import shutil
import os
import sys
import json

from dbbackup.db.base import get_connector
from dbbackup.storage import get_storage
from dbbackup.management.commands.dbbackup import Command as DBBackupCommands
from dbbackup.management.commands.dbrestore import Command as DBRestoreCommand
from dbbackup.utils import filename_generate

from django.core.management import call_command
from django.db import DEFAULT_DB_ALIAS, connections
from django.db.migrations.loader import MigrationLoader

DB_SERVERNAME = "scirius"


class SCBackupException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class SCOperation(object):
    def get_migration_levels(self):
        connection = connections[DEFAULT_DB_ALIAS]
        loader = MigrationLoader(connection, ignore_no_migrations=True)
        graph = loader.graph
        app_names = sorted(loader.migrated_apps)
        last_migrations = {}
        for app_name in app_names:
            shown = set()
            for node in graph.leaf_nodes(app_name):
                for plan_node in graph.forwards_plan(node):
                    if plan_node not in shown and plan_node[0] == app_name:
                        # Give it a nice title if it's a squashed one
                        title = plan_node[1]
                        if graph.nodes[plan_node].replaces:
                            title += " (%s squashed migrations)" % len(graph.nodes[plan_node].replaces)
                        # Mark it as applied/unapplied
                        if plan_node in loader.applied_migrations:
                            shown.add(plan_node)
                            last_migrations[app_name] = int(plan_node[1].split('_')[0])
                        else:
                            continue
        connection.close()
        return last_migrations

    def is_migration_level_lower(self, miglevel):
        llevel = self.get_migration_levels()
        for key in llevel:
            # removing application is unlikely so if miglebel don't have a key
            # then it is are older
            if key not in miglevel:
                return True
            if llevel[key] < miglevel[key]:
                return False
        return True


class SCBackup(SCOperation):
    def __init__(self, all_history=False):
        self.no_history = not all_history
        self.dbcommands = DBBackupCommands()
        self.database = settings.DATABASES['default']

    def backup_git_sources(self):
        # Create a tar of the git sources in the target directory
        sys.stdout.write("%s in %s\n" % (settings.GIT_SOURCES_BASE_DIRECTORY, self.directory))
        sources_path = settings.GIT_SOURCES_BASE_DIRECTORY

        ts = tarfile.open(os.path.join(self.directory, 'sources.tar'), 'w')
        call_dir = os.getcwd()
        os.chdir(sources_path)
        ts.add('.')
        ts.close()
        os.chdir(call_dir)

    def backup_db(self):
        self.dbcommands.servername = DB_SERVERNAME
        self.dbcommands.clean = True
        self.dbcommands.encrypt = False
        self.dbcommands.compress = False
        self.dbcommands.database = self.database['NAME']
        self.dbcommands.storage = get_storage()
        self.dbcommands.connector = get_connector()
        self.dbcommands.connector.drop = False
        self.dbcommands.path = os.path.join(self.directory, 'dbbackup')
        self.dbcommands.filename = 'dbbackup'
        self.dbcommands._save_new_backup(self.database)

    def backup_ruleset_middleware(self):
        try:
            __import__("%s.%s" % (settings.RULESET_MIDDLEWARE, 'backup'))
        except ImportError:
            return

        probe_class = __import__(settings.RULESET_MIDDLEWARE)
        probe_class.backup.backup(self.directory, self.no_history)

    def write_migration_level(self):
        last_migrations = self.get_migration_levels()
        migfile = os.path.join(self.directory, 'miglevel')

        with open(migfile, 'w') as miglevel:
            miglevel.write(json.dumps(last_migrations))

    def run(self):
        self.directory = tempfile.mkdtemp()
        self.write_migration_level()
        self.backup_db()
        self.backup_git_sources()
        self.backup_ruleset_middleware()
        # create tar archive of dir
        call_dir = os.getcwd()
        os.chdir(self.directory)
        filename = filename_generate('tar.bz2', self.dbcommands.database, self.dbcommands.servername)
        outputfile = tempfile.SpooledTemporaryFile()
        ts = tarfile.open(filename, 'w:bz2', fileobj=outputfile)

        for dfile in os.listdir('.'):
            ts.add(dfile)

        ts.close()
        self.dbcommands.storage.write_file(outputfile, filename)
        shutil.rmtree(self.directory)
        os.chdir(call_dir)
        sys.stdout.write('Backup done: %s\n' % filename)


class SCRestore(SCOperation):
    def __init__(self, filepath=None):
        self.database = settings.DATABASES['default']
        self.dbcommands = DBRestoreCommand()
        self.dbcommands.uncompress = False
        self.dbcommands.decrypt = False
        self.dbcommands.storage = get_storage()
        self.dbcommands.connector = get_connector()
        self.dbcommands.servername = DB_SERVERNAME
        self.dbcommands.interactive = False
        self.dbcommands.passphrase = None
        self.dbcommands.database_name = 'default'
        self.dbcommands.database = self.database
        self.dbcommands.filename = filepath
        self.filepath = filepath

    def restore_git_sources(self):
        sys.stdout.write("Restoring to %s from %s\n" % (settings.GIT_SOURCES_BASE_DIRECTORY, self.directory))
        ts = tarfile.open(os.path.join(self.directory, 'sources.tar'), 'r')
        shutil.rmtree(settings.GIT_SOURCES_BASE_DIRECTORY, ignore_errors=True)

        if not os.path.exists(settings.GIT_SOURCES_BASE_DIRECTORY):
            os.mkdir(settings.GIT_SOURCES_BASE_DIRECTORY)

        os.chdir(settings.GIT_SOURCES_BASE_DIRECTORY)
        ts.extractall()

    def restore_db(self):
        self.dbcommands.path = os.path.join(self.directory, 'dbbackup')
        self.dbcommands._restore_backup()

    def restore_ruleset_middleware(self):
        try:
            __import__("%s.%s" % (settings.RULESET_MIDDLEWARE, 'backup'))
        except ImportError:
            return
        probe_class = __import__(settings.RULESET_MIDDLEWARE)
        probe_class.backup.restore(self.directory)

    def test_migration_level(self):
        miglevel = None
        with open(os.path.join(self.directory, 'miglevel'), 'r') as migfile:
            miglevel = json.load(migfile)
        return self.is_migration_level_lower(miglevel)

    def run(self):
        # extract archive in tmp directory
        inputfile = self.dbcommands.storage.read_file(self.dbcommands.filename)
        call_dir = os.getcwd()
        ts = tarfile.open(self.dbcommands.filename, 'r', fileobj=inputfile)
        tmpdir = tempfile.mkdtemp()
        os.chdir(tmpdir)
        ts.extractall()
        ts.close()
        self.directory = tmpdir
        if self.test_migration_level() is False:
            raise SCBackupException(
                "Backup is newer than local Scirius version, please update local instance and apply migrations."
            )
        self.restore_git_sources()
        self.restore_db()

        # Apply upgrades
        call_command('migrate', '--noinput')

        self.restore_ruleset_middleware()
        shutil.rmtree(tmpdir)
        os.chdir(call_dir)
