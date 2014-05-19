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
import urllib2
import tempfile
import tarfile
import re
from datetime import datetime
import sys
import os
import git
import shutil

# Create your models here.

class Source(models.Model):
    FETCH_METHOD = (
        ('http', 'HTTP URL'),
#        ('https', 'HTTPS URL'),
        ('local', 'Upload'),
    )
    CONTENT_TYPE = (
        ('sigs', 'Signature files'),
#        ('iprep', 'IP reputation files'),
#        ('other', 'Other content'),
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

    def __unicode__(self):
        return self.name

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
                    category.get_rules()
                else:
                    category[0].get_rules()
                # get rules in this category

    def handle_rules_in_tar(self, f):
        self.updated_date = datetime.now()
        first_run = False
        # extract file
        if (not tarfile.is_tarfile(f.name)):
            raise OSError("Invalid tar file")
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
            repo = git.Repo(source_git_dir)
            first_run = True
        else:
            try:
                shutil.rmtree(os.path.join(source_git_dir, "rules"))
            except OSError:
                print("Can not delete directory")
                pass
            repo = git.Repo(source_git_dir)
        f.seek(0)
        tfile = tarfile.open(fileobj=f)
        # FIXME This test is only for rules archive
        for member in tfile.getmembers():
            if not member.name.startswith("rules"):
                raise SuspiciousOperation("Suspect tar file contains a invalid name '%s'" % (member.name))
        tfile.extractall(path=source_git_dir)
        index = repo.index
        if len(index.diff(None)) or first_run:
            index.add(["rules"])
            message =  'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        # look for SourceAtVersion with name and HEAD
        # Update updated_date
        sversions  = SourceAtVersion.objects.filter(source = self, version = 'HEAD')
        if sversions:
            sversions[0].updated_date = self.updated_date
            sversions[0].save()
        else:
            sversion = SourceAtVersion.objects.create(source = self, version = 'HEAD',
                                                    updated_date = self.updated_date, git_version = 'HEAD')
        # Get categories
        self.get_categories(tfile)

    def update(self):
        if not self.method in ['http', 'local']:
            raise FieldError("Currently unsupported method")
        if self.update_ruleset:
            f = tempfile.NamedTemporaryFile(dir=self.TMP_DIR)
            self.update_ruleset(f)
            self.handle_rules_in_tar(f)

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
        repo.git.checkout(version)
        # copy file to target
        src_files = os.listdir(source_git_dir)
        for file_name in src_files:
            # don't copy original rules file to dest
            if file_name.endswith('.rules'):
                continue
            full_file_name = os.path.join(source_git_dir, file_name)
            if (os.path.isfile(full_file_name)):
                shutil.copy(full_file_name, directory)
        repo.git.checkout('master')

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('source', args=[str(self.id)])

    def update_ruleset_http(self, f):
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
            #print "One piece"
            f.write(chunk)

    def handle_uploaded_file(self, f):
        dest = tempfile.NamedTemporaryFile(dir=self.TMP_DIR)
        for chunk in f.chunks():
            dest.write(chunk)
        dest.seek(0)
        self.handle_rules_in_tar(dest)

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

    def get_rules(self):
        # parse file
        getsid = re.compile("sid:(\d+)")
        getrev = re.compile("rev:(\d+)")
        getmsg = re.compile("msg:\"(.*?)\"")
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.source.pk))
        rfile = open(os.path.join(source_git_dir, self.filename))

        existing_rules_hash = {}
        for rule in Rule.objects.all():
            existing_rules_hash[rule.sid] = rule
        rules_list = []
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
            rev = match.groups()[0]
            match = getmsg.search(line)
            if not match:
                msg = ""
            else:
                msg = match.groups()[0]
            # FIXME detect if nothing has changed to avoir rules reload
            if existing_rules_hash.has_key(int(sid)):
                # FIXME update references if needed
                rule = existing_rules_hash[int(sid)]
                if rule.rev > rev:
                    rule.content = line
                    rule.rev = rev
                    if rule.category != self:
                        rule.category = self
                    rule.save()
            else:
                rule = Rule(category = self, sid = sid,
                                    rev = rev, content = line, msg = msg)
                rules_list.append(rule)
        if len(rules_list):
            Rule.objects.bulk_create(rules_list)

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
