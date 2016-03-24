"""
Copyright(C) 2014, 2015 Stamus Networks
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
from django.utils import timezone
import requests
import tempfile
import tarfile
import re
import sys
import os
import git
import shutil
import json
import IPy

# Create your models here.

class SystemSettings(models.Model):
    use_http_proxy = models.BooleanField(default=False)
    http_proxy = models.CharField(max_length=200, default="", blank=True)
    https_proxy = models.CharField(max_length=200, default="", blank=True)
    use_elasticsearch = models.BooleanField(default=True)

    def get_proxy_params(self):
        if self.use_http_proxy:
            return { 'http': self.http_proxy, 'https': self.https_proxy }
        else:
            return None

def get_system_settings():
    gsettings = SystemSettings.objects.all()
    if len(gsettings):
        return gsettings[0]
    else:
        gsettings = SystemSettings.objects.create()
        if settings.USE_ELASTICSEARCH:
            gsettings.use_elasticsearch = True
        else:
            gsettings.use_elasticsearch = False
        if settings.USE_PROXY:
            gsettings.use_http_proxy = True
            gsettings.http_proxy = settings.PROXY_PARAMS['http']
            gsettings.https_proxy = settings.PROXY_PARAMS['https']
        else:
            gsettings.use_http_proxy = False
        gsettings.save()
        return gsettings

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
    authkey = models.CharField(max_length=400, blank = True, null = True)

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
        if len(Flowbit.objects.filter(source = self)) == 0:
            self.init_flowbits = True
        else:
            self.init_flowbits = False

    def delete(self):
        self.needs_test()
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
                                            name = name, created_date = timezone.now(),
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
        f.seek(0)
        if (not tarfile.is_tarfile(f.name)):
            raise OSError("Invalid tar file")

        self.updated_date = timezone.now()
        self.first_run = False

        repo = self.get_git_repo(delete = True)

        f.seek(0)
        # extract file
        tfile = tarfile.open(fileobj=f)
        dir_list = []
        for member in tfile.getmembers():
            # only file and dir are allowed
            if not (member.isfile() or member.isdir()):
                raise SuspiciousOperation("Suspect tar file contains non regular file '%s'" % (member.name))
            # don't allow tar file with file in root dir
            if member.isfile() and not '/' in member.name:
                raise SuspiciousOperation("Suspect tar file contains file in root directory '%s'" % (member.name))
            if member.isdir() and not '/' in member.name:
                dir_list.append(member.name)

        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        tfile.extractall(path=source_git_dir)
        index = repo.index
        if len(index.diff(None)) or self.first_run:
            os.environ['USERNAME'] = 'scirius'
            index.add(dir_list)
            message =  'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        self.create_sourceatversion()
        # Get categories
        self.get_categories(tfile)

    def handle_other_file(self, f):
        self.updated_date = timezone.now()
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
            index.add(['rules'])
            message =  'source version at %s' % (self.updated_date)
            index.commit(message)

        self.save()
        # Now we must update SourceAtVersion for this source
        # or create it if needed
        self.create_sourceatversion()

    def handle_rules_file(self, f):

        self.updated_date = timezone.now()
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
                                    name = '%s Sigs' % (self.name), created_date = timezone.now(),
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
            created_date = timezone.now(),
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
        self.needs_test()

    def diff(self):
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        if not os.path.isdir(source_git_dir):
            raise IOError("You have to update source first")
        repo = git.Repo(source_git_dir)
        hcommit = repo.head.commit
        return hcommit.diff('HEAD~1', create_patch = True)

    def export_files(self, directory, version):
        source_git_dir = os.path.join(settings.GIT_SOURCES_BASE_DIRECTORY, str(self.pk))
        repo = git.Repo(source_git_dir)
        with tempfile.TemporaryFile(dir=self.TMP_DIR) as f:
            repo.archive(f, treeish=version)
            f.seek(0)
            # extract file
            tfile = tarfile.open(fileobj=f)
            # copy file to target
            src_files = tfile.getmembers()
            for member in src_files:
                # only consider extra files in rules directory
                if not member.name.startswith('rules/'):
                    continue
                # don't copy original rules file to dest
                if member.name.endswith('.rules') and not self.datatype == 'other':
                    continue
                if member.isfile():
                    member.name = os.path.join(*member.name.split("/", 2)[1:])
                    mfile = tfile.extract(member, path=directory)

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('source', args=[str(self.id)])

    def update_ruleset_http(self, f):
        proxy_params = get_system_settings().get_proxy_params()
        if self.authkey:
            hdrs = { 'Authorization': self.authkey }
        else:
            hdrs = None
        try:
            if proxy_params:
                resp = requests.get(self.uri, proxies = proxy_params, headers = hdrs)
            else:
                resp = requests.get(self.uri, headers = hdrs)
            resp.raise_for_status()
        except requests.exceptions.ConnectionError:
            raise IOError("Connection error, please check URL")
        except requests.exceptions.HTTPError:
            if resp.status_code == 404:
                raise IOError("URL not found on server (error 404), please check URL")
            raise IOError("HTTP error %d sent by server, please check URL or server" % (resp.status_code))
        except requests.exceptions.Timeout:
            raise IOError("Request timeout, server may be down")
        except requests.exceptions.TooManyRedirects:
            raise IOError("Too many redirects, server may be broken")
        f.write(resp.content)

    def handle_uploaded_file(self, f):
        dest = tempfile.NamedTemporaryFile(dir=self.TMP_DIR)
        for chunk in f.chunks():
            dest.write(chunk)
        dest.seek(0)
        if self.datatype == 'sigs':
            self.handle_rules_in_tar(dest)
        elif self.datatype == 'sig':
            self.handle_rules_file(dest)
        elif self.datatype == 'other':
            self.handle_other_file(dest)

    def new_uploaded_file(self, f, firstimport):
        self.handle_uploaded_file(f)
        if not self.datatype == 'other' and not firstimport:
            self.create_update()
        for rule in self.updated_rules["deleted"]:
            rule.delete()
        self.needs_test()

    def needs_test(self):
        try:
            sourceatversion = SourceAtVersion.objects.get(source = self, version = 'HEAD')
        except:
            return
        rulesets = Ruleset.objects.all()
        for ruleset in rulesets:
            if sourceatversion in ruleset.sources.all():
                ruleset.needs_test()

class SourceAtVersion(models.Model):
    source = models.ForeignKey(Source)
    # Sha1 or HEAD or tag
    version = models.CharField(max_length=42)
    git_version = models.CharField(max_length=42, default = 'HEAD')
    updated_date = models.DateTimeField('date updated', blank = True, default = timezone.now)

    def __unicode__(self):
        return str(self.source) + "@" + self.version

    def _get_name(self):
        return str(self)

    name = property(_get_name)

    def export_files(self, directory):
        self.source.export_files(directory, self.version)

    def to_buffer(self):
        categories = Category.objects.filter(source = self.source)
        rules = Rule.objects.filter(category__in = categories)
        file_content = "# Rules file for " + self.name + " generated by Scirius at " + str(timezone.now()) + "\n"
        rules_content = [ rule.content for rule in rules ]
        file_content += "\n".join(rules_content)
        return file_content


    def test_rule_buffer(self, rule_buffer, single = False):
        Probe = __import__(settings.RULESET_MIDDLEWARE)
        testor = Probe.common.Test()
        tmpdir = tempfile.mkdtemp()
        self.export_files(tmpdir)
        related_files = {}
        for root, _, files in os.walk(tmpdir):
            for f in files:
                fullpath = os.path.join(root, f)
                if os.path.getsize(fullpath) < 50 * 1024:
                    with open(fullpath, 'r') as cf:
                        related_files[f] = cf.read()
        shutil.rmtree(tmpdir)
        if single:
            return testor.rule(rule_buffer, related_files = related_files)
        else:
            return testor.rules(rule_buffer, related_files = related_files)

    def test(self):
        rule_buffer = self.to_buffer()
        return self.test_rule_buffer(rule_buffer)

class SourceUpdate(models.Model):
    source = models.ForeignKey(Source)
    created_date = models.DateTimeField('date of update', blank = True, default = timezone.now)
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
    created_date = models.DateTimeField('date created', default = timezone.now)
    source = models.ForeignKey(Source)

    getflowbits = re.compile("flowbits *: *(isset|set),(.*?) *;")

    class Meta:
        verbose_name_plural = "categories"

    def __unicode__(self):
        return self.name

    def parse_rule_flowbit(self, source, line):
        flowbits = []
        match = self.getflowbits.findall(line)
        if match:
            for flowinst in match:
               elt = Flowbit.objects.filter(source = source, name = flowinst[1])
               if elt:
                   elt = elt[0]
                   if flowinst[0] == "isset" and not elt.isset:
                       elt.isset = True
                       elt.save()
                   if flowinst[0] == "set" and not elt.set:
                       elt.set = True
                       elt.save()
               else:
                   if flowinst[0] == "isset":
                       fisset = True
                       fset = False
                   else:
                       fisset = False
                       fset = True
                   elt = Flowbit(name = flowinst[1], source = source, isset = fisset, set = fset)
                   elt.save()
               flowbits.append(elt)
        return flowbits

    def get_rules(self, source):
        # parse file
        # return an object with updates
        getsid = re.compile("sid *: *(\d+)")
        getrev = re.compile("rev *: *(\d+)")
        getmsg = re.compile("msg *: *\"(.*?)\"")
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

        # If no flowbits are knowned in the source we try
        # to parse them all. There should be no database query for ruleset
        # that are not using them. If there is some, then do it only in update.
        with transaction.atomic():
            for line in rfile.readlines():
                state = True
                if line.startswith('#'):
                    # check if it is a commented signature
                    if "->" in line and "sid" in line and ")" in line:
                        line = line.lstrip("# ")
                        state = False
                    else:
                        continue
                match = getsid.search(line)
                if not match:
                    continue
                sid = match.groups()[0]
                match = getrev.search(line)
                if match:
                    rev = int(match.groups()[0])
                else:
                    rev = None
                match = getmsg.search(line)
                if not match:
                    msg = ""
                else:
                    msg = match.groups()[0]
                flowbits = []
                if source.init_flowbits:
                    flowbits = self.parse_rule_flowbit(source, line)
                # FIXME detect if nothing has changed to avoir rules reload
                if existing_rules_hash.has_key(int(sid)):
                    # FIXME update references if needed
                    rule = existing_rules_hash[int(sid)]
                    if rev == None or rule.rev < rev or source.init_flowbits:
                        rule.content = line
                        if rev == None:
                            rule.rev = 0
                        else:
                            rule.rev = rev
                        if rule.category != self:
                            rule.category = self
                        if not source.init_flowbits:
                            flowbits = self.parse_rule_flowbit(source, line)
                        rule.flowbits = flowbits
                        rules_update["updated"].append(rule)
                        rule.save()
                    else:
                        rules_unchanged.append(rule)
                else:
                    if rev == None:
                        rev = 0
                    rule = Rule(category = self, sid = sid,
                                        rev = rev, content = line, msg = msg,
                                        state_in_source = state, state = state)
                    if not source.init_flowbits:
                        flowbits = self.parse_rule_flowbit(source, line)
                    rule.flowbits = flowbits
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

class Flowbit(models.Model):
    name = models.CharField(max_length=100)
    set = models.BooleanField(default=False)
    isset = models.BooleanField(default=False)
    enable = models.BooleanField(default=True)
    source = models.ForeignKey(Source)

class Rule(models.Model):
    sid = models.IntegerField(primary_key=True)
    category = models.ForeignKey(Category)
    msg = models.CharField(max_length=1000)
    state = models.BooleanField(default=True)
    state_in_source = models.BooleanField(default=True)
    rev = models.IntegerField(default=0)
    content = models.CharField(max_length=10000)
    flowbits = models.ManyToManyField(Flowbit)

    hits = 0

    def __unicode__(self):
        return str(self.sid) + ":" + self.msg

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('rule', args=[str(self.sid)])

    def get_flowbits_group(self):
        rules = set()
        for flowbit in self.flowbits.all():
            rules_dep = Rule.objects.filter(category = self.category, flowbits = flowbit)
            rules |= set(rules_dep)
        return rules

    def enable(self, ruleset):
        enable_rules = self.get_flowbits_group()
        if not enable_rules:
            enable_rules |= {self}
        ruleset.enable_rules(enable_rules)
        return

    def disable(self, ruleset):
        disable_rules = self.get_flowbits_group()
        if not disable_rules:
            disable_rules |= {self}
        ruleset.disable_rules(disable_rules)
        return

    def test(self, ruleset):
        return ruleset.test_rule_buffer(self.content, single = True)

    def toggle_availability(self):
        toggle_rules = self.get_flowbits_group()
        self.category.source.needs_test()
        if not toggle_rules:
            toggle_rules |= {self}
        for rule in toggle_rules:
            rule.state = not rule.state
            rule.save()

# we should use django reversion to keep track of this one
# even if fixing HEAD may be complicated
class Ruleset(models.Model):
    name = models.CharField(max_length=100, unique = True)
    descr = models.CharField(max_length=400, blank = True)
    created_date = models.DateTimeField('date created')
    updated_date = models.DateTimeField('date updated', blank = True)
    need_test = models.BooleanField(default=True)
    validity = models.BooleanField(default=True)
    errors = models.TextField(blank = True)
    rules_count = models.IntegerField(default=0)

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

    def _json_errors(self):
        return json.loads(self.errors)

    json_errors = property(_json_errors)

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('ruleset', args=[str(self.id)])

    def update(self):
        sourcesatversion = self.sources.all()
        for sourcesat in sourcesatversion:
            sourcesat.source.update()
        self.updated_date = timezone.now()
        self.need_test = True
        self.save()

    def generate(self):
        rules = Rule.objects.filter(category__in = self.categories.all(), state = True)
        # remove suppressed list
        rules = list(set(rules.all()) - set(self.suppressed_rules.all()))
        return rules

    def generate_threshold(self, directory):
        thresholdfile = os.path.join(directory, 'threshold.config')
        with open(thresholdfile, 'w') as f:
            for threshold in Threshold.objects.filter(ruleset = self):
                f.write("%s\n" % (threshold))

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
        self.save()
        return self

    def export_files(self, directory):
        for src in self.sources.all():
            src.export_files(directory)
        # generate threshold.config
        self.generate_threshold(directory)

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

    def to_buffer(self):
        rules = self.generate()
        self.rules_count = len(rules)
        file_content = "# Rules file for " + self.name + " generated by Scirius at " + str(timezone.now()) + "\n"
        rules_content = [ rule.content for rule in rules ]
        file_content += "\n".join(rules_content)
        return file_content

    def test_rule_buffer(self, rule_buffer, single = False):
        Probe = __import__(settings.RULESET_MIDDLEWARE)
        testor = Probe.common.Test()
        tmpdir = tempfile.mkdtemp()
        self.export_files(tmpdir)
        related_files = {}
        for root, _, files in os.walk(tmpdir):
            for f in files:
                fullpath = os.path.join(root, f)
                with open(fullpath, 'r') as cf:
                    related_files[f] = cf.read( 50 * 1024)
        shutil.rmtree(tmpdir)
        if single:
            return testor.rule(rule_buffer, related_files = related_files)
        else:
            return testor.rules(rule_buffer, related_files = related_files)

    def test(self):
        self.need_test = False
        rule_buffer = self.to_buffer()
        result = self.test_rule_buffer(rule_buffer)
        result['rules_count'] = self.rules_count
        self.validity = result['status']
        if result.has_key('errors'):
            self.errors = json.dumps(result['errors'])
        else:
            self.errors = json.dumps([])
        self.save()
        return result

    def disable_rules(self, rules):
        self.suppressed_rules.add(*rules)
        self.needs_test()

    def enable_rules(self, rules):
        self.suppressed_rules.remove(*rules)
        self.needs_test()
    
    def needs_test(self):
        self.need_test = True
        self.save()

class Threshold(models.Model):
    THRESHOLD_TYPES = (('threshold', 'threshold'), ('event_filter', 'event_filter'), ('suppress', 'suppress'))
    THRESHOLD_TYPE_TYPES = (('limit', 'limit'), ('threshold', 'threshold'), ('both', 'both'))
    TRACK_BY_CHOICES= (('by_src', 'by_src'),('by_dst', 'by_dst'))
    descr = models.CharField(max_length=400, blank = True)
    threshold_type = models.CharField(max_length=20, choices=THRESHOLD_TYPES, default='suppress')
    type = models.CharField(max_length=20, choices=THRESHOLD_TYPE_TYPES, default='limit')
    gid = models.IntegerField(default=1)
    rule = models.ForeignKey(Rule, default = None)
    ruleset = models.ForeignKey(Ruleset, default = None)
    track_by = models.CharField(max_length= 10, choices = TRACK_BY_CHOICES, default='by_src')
    net = models.CharField(max_length=100, blank = True)
    count = models.IntegerField(default=1)
    seconds = models.IntegerField(default=60)

    def __unicode__(self):
        rep = ""
        if self.threshold_type == "suppress":
            rep = "suppress gen_id %d, sig_id %d" % (self.gid, self.rule.sid)
            rep += ", track %s, ip %s" % (self.track_by, self.net)
        else:
            rep = "%s gen_id %d, sig_id %d, type %s, track %s, count %d, seconds %d" % (self.threshold_type, self.gid, self.rule.sid, self.type, self.track_by, self.count, self.seconds)
        return rep

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('threshold', args=[str(self.id)])

    def contain(self, elt):
        if elt.threshold_type != self.threshold_type:
            return False
        if elt.track_by != self.track_by:
            return False
        if elt.threshold_type == 'suppress':
            if not IPy.IP(self.net).overlaps(IPy.IP(elt.net)):
                return False
        return True

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
