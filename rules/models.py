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

from django.db import models
from django.conf import settings
from django.core.exceptions import FieldError, SuspiciousOperation
from django.db import transaction
import urllib2
import tempfile
import tarfile
import re
from datetime import datetime
import sys
import os
import git
import shutil
import json

# Create your models here.

class Source(models.Model):
    FETCH_METHOD = (
        ('http', 'HTTP URL'),
#        ('https', 'HTTPS URL'),
        ('local', 'Upload'),
    )
    CONTENT_TYPE = (
        ('sigs', 'Signatures files in tar archive'),
        ('sig', 'Individual Signatures file'),
#        ('iprep', 'IP reputation files'),
        ('other', 'Other content'),
    )
    TMP_DIR = "/tmp/"

    name = models.CharField(max_length=100, unique = True)
    created_date = models.DateTimeField('date created')
    updated_date = models.DateTimeField('date updated', blank = True, null = True)
    method = models.CharField(max_length=10, choices=FETCH_METHOD)
    datatype = models.CharField(max_length=10, choices=CONTENT_TYPE)
    uri = models.CharField(max_length=400, blank = True, null = True)

    editable = True
    # git repo where we store the physical thing
    # this allow to store the different versions
    # and to checkout the sources to a given version
    # for ruleset generation
    # Operations
    #  - Create
    #  - Delete
    #  - Update: only custom one
    #    Use method to get new files and commit them
    #    Create a new SourceAtVersion when there is a real update
    #    In case of upload: simply propose user upload form

    def __init__(self, *args, **kwargs):
        models.Model.__init__(self, *args, **kwargs)
        if (self.method == 'http'):
            self.update_ruleset = self.update_ruleset_http
        else:
            self.update_ruleset = None
        self.first_run = False
        self.updated_rules = {"added": [], "deleted": [], "updated": []}

    def delete(self):
        # delete git tree
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        try:
            shutil.rmtree(source_git_dir)
        # Ignore error if not present
        except OSError:
            pass
        # delete model
        models.Model.delete(self)

    def __unicode__(self):
        return self.name

    def aggregate_update(self, update):
        self.updated_rules["added"] = list(set(self.updated_rules["added"]).union(set(update["added"])))
        self.updated_rules["deleted"] = list(set(self.updated_rules["deleted"]).union(set(update["deleted"])))
        self.updated_rules["updated"] = list(set(self.updated_rules["updated"]).union(set(update["updated"])))

    def get_categories(self, tarfile):
        catname = re.compile("\/(.+)\.rules$")
        for member in tarfile.getmembers():
            if member.name.endswith('.rules'):
                match = catname.search(member.name)
                name = match.groups()[0]
                category = Category.objects.filter(source = self, name = name)
                if not category:
                    category = Category.objects.create(source = self,
                                            name = name, created_date = datetime.now(),
                                            filename = member.name)
                    category.get_rules(self)
                else:
                    category[0].get_rules(self)
                # get rules in this category

    def get_git_repo(self, delete = False):
        # check if git tree is in place
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        if not os.path.isdir(source_git_dir):
            if os.path.isfile(source_git_dir):
                raise OSError("git-sources is not a directory")
            os.makedirs(source_git_dir)
            repo = git.Repo.init(source_git_dir)
            config = repo.config_writer()
            config.set_value("user", "email", "scirius@stamus-networks.com")
            config.set_value("user", "name", "Scirius")
            del(config)
            del(repo)
            repo = git.Repo(source_git_dir)
            self.first_run = True
        else:
            if delete:
                try:
                    shutil.rmtree(os.path.join(source_git_dir, "rules"))
                except OSError:
                    print("Can not delete directory")
                    pass
            repo = git.Repo(source_git_dir)
        return repo

    def create_sourceatversion(self, version='HEAD'):
        # look for SourceAtVersion with name and HEAD
        # Update updated_date
        sversions  = SourceAtVersion.objects.filter(source = self, version = version)
        if sversions:
            sversions[0].updated_date = self.updated_date
            sversions[0].save()
        else:
            sversion = SourceAtVersion.objects.create(source = self, version = version,
                                                    updated_date = self.updated_date, git_version = version)

    def handle_rules_in_tar(self, f):
        if (not tarfile.is_tarfile(f.name)):
            raise OSError("Invalid tar file")

        self.updated_date = datetime.now()
        self.first_run = False

        repo = self.get_git_repo(delete = True)

        f.seek(0)
        # extract file
        tfile = tarfile.open(fileobj=f)
        # FIXME This test is only for rules archive
        for member in tfile.getmembers():
            if not member.name.startswith("rules"):
                raise SuspiciousOperation("Suspect tar file contains a invalid name '%s'" % (member.name))

        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        tfile.extractall(path=source_git_dir)
        index = repo.index
        if len(index.diff(None)) or self.first_run:
            os.environ['USERNAME'] = 'scirius'
            index.add(["rules"])
            message =  'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        self.create_sourceatversion()
        # Get categories
        self.get_categories(tfile)

    # FIXME we need a factorization here with handle_rules_file
    def handle_other_file(self, f):
        self.updated_date = datetime.now()
        self.first_run = False

        repo = self.get_git_repo(delete = True)

        rules_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), 'rules')
        # create rules dir if needed
        if not os.path.isdir(rules_dir):
            os.makedirs(rules_dir)
        # copy file content to target
        f.seek(0)
        os.fsync(f)
        shutil.copy(f.name, os.path.join(rules_dir, self.name))

        index = repo.index
        if len(index.diff(None)) or self.first_run:
            os.environ['USERNAME'] = 'scirius'
            index.add(["rules"])
            message =  'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        self.create_sourceatversion()

    def handle_rules_file(self, f):

        self.updated_date = datetime.now()
        self.first_run = False

        repo = self.get_git_repo(delete = True)

        rules_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), 'rules')
        # create rules dir if needed
        if not os.path.isdir(rules_dir):
            os.makedirs(rules_dir)
        # copy file content to target
        f.seek(0)
        os.fsync(f)
        shutil.copy(f.name, os.path.join(rules_dir, 'sigs.rules'))

        index = repo.index
        if len(index.diff(None)) or self.first_run:
            os.environ['USERNAME'] = 'scirius'
            index.add(["rules"])
            message =  'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        self.create_sourceatversion()
        # category based on filename
        category = Category.objects.filter(source = self, name = '%s Sigs' % (self.name))
        if not category:
            category = Category.objects.create(source = self,
                                    name = '%s Sigs' % (self.name), created_date = datetime.now(),
                                    filename = os.path.join('rules', 'sigs.rules'))
            category.get_rules(self)
        else:
            category[0].get_rules(self)

    def json_rules_list(self, rlist):
        rules = []
        for rule in rlist:
            rules.append({"sid":rule.sid, "msg": rule.msg,
                "category": rule.category.name,
                "pk": rule.pk })
        # for each rule we create a json object sid + msg + content
        return rules

    def create_update(self):
        # for each set
        update = {}
        update["deleted"] = self.json_rules_list(self.updated_rules["deleted"])
        update["added"] = self.json_rules_list(self.updated_rules["added"])
        update["updated"] = self.json_rules_list(self.updated_rules["updated"])
        repo = self.get_git_repo(delete = False)
        sha = repo.heads.master.log()[-1].newhexsha
        SourceUpdate.objects.create(
            source = self,
            created_date = datetime.now(),
            data = json.dumps(update),
            version = sha,
            changed = len(update["deleted"]) + len(update["added"]) + len(update["updated"]),
        )

    @transaction.atomic
    def update(self):
        # look for categories list: if none, first import
        categories = Category.objects.filter(source = self)
        firstimport = False
        if not categories:
            firstimport = True
        if not self.method in ['http', 'local']:
            raise FieldError("Currently unsupported method")
        if self.update_ruleset:
            f = tempfile.NamedTemporaryFile(dir=self.TMP_DIR)
            self.update_ruleset(f)
            if self.datatype == 'sigs':
                self.handle_rules_in_tar(f)
            elif self.datatype == 'sig':
                self.handle_rules_file(f)
            elif self.datatype == 'other':
                self.handle_other_file(f)
        if not self.datatype == 'other' and not firstimport:
            self.create_update()
        for rule in self.updated_rules["deleted"]:
            rule.delete()

    def diff(self):
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        if not os.path.isdir(source_git_dir):
            # FIXME exit clean here
            raise IOError("You have to update source first")
        repo = git.Repo(source_git_dir)
        hcommit = repo.head.commit
        return hcommit.diff('HEAD~1', create_patch = True)

    def export_files(self, directory, version):
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk), "rules")
        repo = git.Repo(source_git_dir)
        with tempfile.TemporaryFile(dir=self.TMP_DIR) as f:
            repo.archive(f, treeish=version)
            f.seek(0)
            # extract file
            tfile = tarfile.open(fileobj=f)
            # copy file to target
            src_files = tfile.getmembers()
            for member in src_files:
                # don't copy original rules file to dest
                if member.name.endswith('.rules') and not self.datatype == 'other':
                    continue
                if member.isfile():
                    tfile.extract(member, path=directory)

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('source', args=[str(self.id)])

    def update_ruleset_http(self, f):
        if settings.USE_PROXY:
            proxy_handler = urllib2.ProxyHandler({'http':settings.PROXY_PARAMS['http'],
                                                  'https':settings.PROXY_PARAMS['https'] })
            if settings.PROXY_PARAMS['user']:
                password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
                password_mgr.add_password(None,
                                    settings.PROXY_PARAMS['http'],
                                    settings.PROXY_PARAMS['user'],
                                    settings.PROXY_PARAMS['pass'])
                proxy_auth_handler = urllib2.ProxyBasicAuthHandler(password_mgr)
                opener = urllib2.build_opener(proxy_handler, proxy_auth_handler)
            else:
                opener = urllib2.build_opener(proxy_handler)
            urllib2.install_opener(opener)
        resp = urllib2.urlopen(self.uri)
        if resp.code == 404:
            raise IOError("File not found, please check URL")
        elif not resp.code == 200:
            raise IOError("Invalid response code %d for %" % (resp.code) )
        CHUNK = 256 * 1024
        while True:
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            f.write(chunk)

    def handle_uploaded_file(self, f):
        dest = tempfile.NamedTemporaryFile(dir=self.TMP_DIR)
        for chunk in f.chunks():
            dest.write(chunk)
        dest.seek(0)
        if self.datatype == 'sigs':
            self.handle_rules_in_tar(dest)
        elif self.datatype == 'sig':
            self.handle_rules_file(dest)

class SourceAtVersion(models.Model):
    source = models.ForeignKey(Source)
    # Sha1 or HEAD or tag
    version = models.CharField(max_length=42)
    git_version = models.CharField(max_length=42, default = 'HEAD')
    updated_date = models.DateTimeField('date updated', blank = True, default = datetime.now())

    def __unicode__(self):
        return str(self.source) + "@" + self.version

    def _get_name(self):
        return str(self)

    def export_files(self, directory):
        self.source.export_files(directory, self.version)

    name = property(_get_name)

class SourceUpdate(models.Model):
    source = models.ForeignKey(Source)
    created_date = models.DateTimeField('date of update', blank = True, default = datetime.now())
    # Store update info as a JSON document
    data = models.TextField()
    version = models.CharField(max_length=42)
    changed = models.IntegerField(default=0)

    def diff(self):
        data = json.loads(self.data)
        diff = data
        diff['stats'] = {'updated':len(data['updated']), 'added':len(data['added']), 'deleted':len(data['deleted'])}
        diff['date'] = self.created_date
        return diff

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('sourceupdate', args=[str(self.id)])

class Category(models.Model):
    name = models.CharField(max_length=100)
    filename = models.CharField(max_length=200)
    descr = models.CharField(max_length=400, blank = True)
    created_date = models.DateTimeField('date created', default = datetime.now())
    source = models.ForeignKey(Source)

    class Meta:
        verbose_name_plural = "categories"

    def __unicode__(self):
        return self.name

    def get_rules(self, source):
        # parse file
        # return an object with updates
        getsid = re.compile("sid *:(\d+)")
        getrev = re.compile("rev *:(\d+)")
        getmsg = re.compile("msg *:\"(.*?)\"")
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.source.pk))
        rfile = open(os.path.join(source_git_dir, self.filename))

        rules_update = {"added": [], "deleted": [], "updated": []}
        rules_unchanged = []

        existing_rules_hash = {}
        for rule in Rule.objects.all():
            existing_rules_hash[rule.sid] = rule
        rules_list = []
        for rule in Rule.objects.filter(category = self):
            rules_list.append(rule)
        with transaction.atomic():
            for line in rfile.readlines():
                if line.startswith('#'):
                    continue
                match = getsid.search(line)
                if not match:
                    continue
                sid = match.groups()[0]
                match = getrev.search(line)
                if not match:
                    continue
                rev = int(match.groups()[0])
                match = getmsg.search(line)
                if not match:
                    msg = ""
                else:
                    msg = match.groups()[0]
                # FIXME detect if nothing has changed to avoir rules reload
                if existing_rules_hash.has_key(int(sid)):
                    # FIXME update references if needed
                    rule = existing_rules_hash[int(sid)]
                    if rule.rev < rev:
                        rule.content = line
                        rule.rev = rev
                        if rule.category != self:
                            rule.category = self
                        rules_update["updated"].append(rule)
                        rule.save()
                    else:
                        rules_unchanged.append(rule)
                else:
                    rule = Rule(category = self, sid = sid,
                                        rev = rev, content = line, msg = msg)
                    rules_update["added"].append(rule)
            if len(rules_update["added"]):
                Rule.objects.bulk_create(rules_update["added"])
            rules_update["deleted"] = list(set(rules_list) -
                                      set(rules_update["added"]).union(set(rules_update["updated"])) -
                                      set(rules_unchanged))
            source.aggregate_update(rules_update)

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('category', args=[str(self.id)])

class Rule(models.Model):
    sid = models.IntegerField(primary_key=True)
    category = models.ForeignKey(Category)
    msg = models.CharField(max_length=1000)
    state = models.BooleanField(default=True)
    rev = models.IntegerField(default=0)
    content = models.CharField(max_length=10000)

    hits = 0

    def __unicode__(self):
        return str(self.sid) + ":" + self.msg

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('rule', args=[str(self.sid)])

# we should use django reversion to keep track of this one
# even if fixing HEAD may be complicated
class Ruleset(models.Model):
    name = models.CharField(max_length=100, unique = True)
    descr = models.CharField(max_length=400, blank = True)
    created_date = models.DateTimeField('date created')
    updated_date = models.DateTimeField('date updated', blank = True)

    editable = True

    # List of Source that can be used in the ruleset
    # It can be a specific version or HEAD if we want to use
    # latest available
    sources = models.ManyToManyField(SourceAtVersion)
    # List of Category selected in the ruleset
    categories = models.ManyToManyField(Category, blank = True)
    # List or Rules to suppressed from the Ruleset
    # Exported as suppression list in oinkmaster
    suppressed_rules = models.ManyToManyField(Rule, blank = True)
    # Operations
    # Creation:
    #  - define sources
    #  - define version
    #  - define categories
    #  - define suppressed rules
    # Delete
    # Copy
    #  - Specify new name
    # Refresh:
    #  - trigger update of sources
    #  - build new head
    # Update:
    #  - define version
    #  - update link
    # Generate appliance ruleset to directory:
    #  - get files from correct version exported to directory
    # Apply ruleset:
    #  - Tell Ansible to publish

    def __unicode__(self):
        return self.name

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('ruleset', args=[str(self.id)])

    def update(self):
        sourcesatversion = self.sources.all()
        for sourcesat in sourcesatversion:
            sourcesat.source.update()
        self.updated_date = datetime.now()
        self.save()

    def generate(self):
        rules = Rule.objects.filter(category__in = self.categories.all())
        # remove suppressed list
        rules = list(set(rules.all()) - set(self.suppressed_rules.all()))
        return rules

    def copy(self, name):
        orig_sources = self.sources.all()
        orig_categories = self.categories.all()
        orig_supp_rules = self.suppressed_rules.all()
        self.name = name
        self.pk = None
        self.id = None
        self.save()
        self.sources = orig_sources
        self.categories = orig_categories
        self.suppressed_rules = orig_supp_rules
        return self

    def export_files(self, directory):
        for src in self.sources.all():
            src.export_files(directory)

    def diff(self, mode='long'):
        sourcesatversion = self.sources.all()
        sdiff = {}
        for sourceat in sourcesatversion:
            supdate = SourceUpdate.objects.filter(source = sourceat.source).order_by('-created_date')
            if len(supdate) > 0: 
                srcdiff = supdate[0].diff()
                if mode == 'short':
                    num = 0
                    for key in srcdiff['stats']:
                        num = num + srcdiff['stats'][key]
                    if num > 0:
                        sdiff[sourceat.name] = srcdiff
                else:
                    sdiff[sourceat.name] = srcdiff
        return sdiff

def dependencies_check(obj):
    if obj == Source:
        return

    if obj == Ruleset:
        if len(Source.objects.all()) == 0:
            return "You need first to create and update a source."
        if len(SourceAtVersion.objects.all()) == 0:
            return "You need first to update existing source."
        return

    if len(Source.objects.all()) == 0:
            return "You need first to create a source and a ruleset."

    if len(Ruleset.objects.all()) == 0:
            return "You need first to create a ruleset."
