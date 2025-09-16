import os
import tarfile
import tempfile
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from shutil import rmtree
from unittest.mock import patch

from rules.models.model import (
    Rule,
    Source,
    InvalidCategoryException,
    Ruleset,
    UserAction,
)

from rules.api.source import UploadEditSourceTaskSerializer
from .test_misc import RestAPITestBase


ET_URL = "https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz"

RULE_CONTENT = 'alert ip any any -> any any (msg:"Unicode test rule éàç"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)\n'  # ignore_utf8_check: 233 224 231


class SourceCreationTestCase(TestCase):
    def setUp(self):
        self.tmpdirname = tempfile.mkdtemp()
        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            self.source = Source.objects.create(
                name="ET Open", method="http", datatype="sigs", uri=ET_URL, created_date=timezone.now()
            )

    def tearDown(self):
        rmtree(self.tmpdirname)

    def _create_archive_good(
        self, tar_path: str, rules_dir: bool = True, categories_fail: bool = False, list_fail: bool = False
    ):
        """
        rule_dir == False:
            * file_0.rules
            * file_1.rules
            * file_2.rules
            * file_3.rules
            * files-categories.txt
            * file.list

        rule_dir == True:
            * rules/
            * rules/file_0.rules
            * rules/file_1.rules
            * rules/file_2.rules
            * rules/file_3.rules
            * rules/files-categories.txt
            * rules/file.list
        """
        dir_path = tempfile.mkdtemp()
        current_dir = os.getcwd()
        os.chdir(dir_path)
        files_number = 0

        with tarfile.open(tar_path, "w:gz") as tfile:
            for idx in range(4):
                file_path = f"file_{idx}.rules"
                if rules_dir:
                    file_path = os.path.join("rules", file_path)
                    if not os.path.exists("rules"):
                        os.mkdir("rules")

                with open(file_path, "w") as f:
                    f.write(f"{idx}")

                if not rules_dir:
                    tfile.add(file_path)
                files_number += 1

            for file_path in ("file-categories.txt", "file.list"):
                if rules_dir:
                    file_path = os.path.join("rules", file_path)

                fail = list_fail
                msg = "193.42.38.14,%s,100\n"
                if file_path.endswith("categories.txt"):
                    msg = "%s,2527000,ET Threatview.io High Confidence Cobalt Strike C2 IP\n"
                    fail = categories_fail

                with open(file_path, "w") as f:
                    start = 0 if fail else 20
                    for idx in range(start, start + 5):
                        f.write(msg % idx)

                if not rules_dir:
                    tfile.add(file_path)
                files_number += 1

            if rules_dir:
                tfile.add("rules")

        os.chdir(current_dir)
        rmtree(dir_path)
        return files_number

    def _create_archive_no_root_dir(self, tar_path):
        """
        * rules/file_0.rules
        * rules/file_1.rules
        * rules/file_2.rules
        * rules/file_3.rules
        """
        dir_path = tempfile.mkdtemp()
        current_dir = os.getcwd()
        os.chdir(dir_path)
        files_number = 0

        with tarfile.open(tar_path, "w:gz") as tfile:
            for idx in range(4):
                file_path = os.path.join("rules", f"file_{idx}.rules")
                if not os.path.exists("rules"):
                    os.mkdir("rules")

                with open(file_path, "w") as f:
                    f.write(f"{idx}")

                tfile.add(file_path)
                files_number += 1

        os.chdir(current_dir)
        rmtree(dir_path)
        return files_number

    def _create_archive_files_different_levels(self, tar_path: str):
        """
        * file_0.rules
        * rules/file_1.rules
        * rules/file_2.rules
        * rules/file_3.rules
        """
        dir_path = tempfile.mkdtemp()
        current_dir = os.getcwd()
        os.chdir(dir_path)
        files_number = 0

        with tarfile.open(tar_path, "w:gz") as tfile:
            for idx in range(4):
                file_path = os.path.join("rules", f"file_{idx}.rules")

                if idx == 0:
                    file_path = f"file_{idx}.rules"

                if not os.path.exists("rules"):
                    os.mkdir("rules")

                with open(file_path, "w") as f:
                    f.write(f"{idx}")

                tfile.add(file_path)
                files_number += 1

        os.chdir(current_dir)
        rmtree(dir_path)
        return files_number

    def _create_archive_files_dot_prefix(self, tar_path: str, different_levels: bool = False):
        """
           * ./file_0.rules
           * ./rules/file_1.rules
           * ./rules/file_2.rules
           * ./rules/file_3.rules
        Or
           * ./
           * ./file_0.rules
           * ./rules
           * ./rules/file_1.rules
           * ./rules/file_2.rules
           * ./rules/file_3.rules
        """
        dir_path = tempfile.mkdtemp()
        current_dir = os.getcwd()
        os.chdir(dir_path)
        files_number = 0

        with tarfile.open(tar_path, "w:gz") as tfile:
            for idx in range(4):
                file_path = os.path.join("rules", f"file_{idx}.rules")

                if different_levels and idx == 0:
                    file_path = f"file_{idx}.rules"

                if not os.path.exists("rules"):
                    os.mkdir("rules")

                with open(file_path, "w") as f:
                    f.write(f"{idx}")

                files_number += 1
            tfile.add(".")

        os.chdir(current_dir)
        rmtree(dir_path)
        return files_number

    # def test_source_update(self):
    #     """Test source update"""
    #     self.source.update()
    #     self.assertNotEqual(Category.objects.filter(source=self.source).count(), 0)

    def test_unicode_rule(self):
        source = Source.objects.create(name="Unicode rule", method="local", datatype="sig", created_date=timezone.now())

        with tempfile.NamedTemporaryFile(dir=self.tmpdirname) as f:
            f.write(RULE_CONTENT.encode("utf-8"))
            f.seek(0)
            source.handle_rules_file(f)
            self.assertEqual(Rule.objects.count(), 1)

    def test_source_name_depending_on_datatype(self):
        source = Source(name="Unicode rule", method="local", datatype="sig", created_date=timezone.now())
        source.clean()

        source.name = "some/source with sp&cial chars '"
        source.clean()

        source.datatype = "ioc"
        self.assertRaises(ValidationError, source.clean)
        source.datatype = "other"
        self.assertRaises(ValidationError, source.clean)
        source.datatype = "b64dataset"
        self.assertRaises(ValidationError, source.clean)

        source.name = "/tmp/oops-I-did-it-again"
        self.assertRaises(ValidationError, source.clean)
        source.name = "I'm-sorry"
        self.assertRaises(ValidationError, source.clean)

        source.name = "ok-source"
        source.clean()

    def test_archive_dot_prefix(self):
        tar_path = "/tmp/source.tar.gz"
        nb_files = self._create_archive_files_dot_prefix(tar_path)

        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            rules_path = os.path.join(self.tmpdirname, str(self.source.pk), "rules")

            with open(tar_path, "rb") as f:
                self.source.handle_rules_in_tar(f)

            # listdir: list files not recursively
            extracted_files_nb = len(os.listdir(rules_path))
            self.assertEqual(nb_files, extracted_files_nb)

        os.remove(tar_path)

    def test_archive_dot_prefix_different_levels(self):
        tar_path = "/tmp/source.tar.gz"
        nb_files = self._create_archive_files_dot_prefix(tar_path, different_levels=True)

        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            rules_path = os.path.join(self.tmpdirname, str(self.source.pk), "rules")

            with open(tar_path, "rb") as f:
                self.source.handle_rules_in_tar(f)

            # listdir: list files not recursively
            extracted_files_nb = len(os.listdir(rules_path))
            self.assertEqual(nb_files, extracted_files_nb)

        os.remove(tar_path)

    def test_archive_different_levels(self):
        tar_path = "/tmp/source.tar.gz"
        nb_files = self._create_archive_files_different_levels(tar_path)

        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            rules_path = os.path.join(self.tmpdirname, str(self.source.pk), "rules")

            with open(tar_path, "rb") as f:
                self.source.handle_rules_in_tar(f)

            # listdir: list files not recursively
            extracted_files_nb = len(os.listdir(rules_path))
            self.assertEqual(nb_files, extracted_files_nb)

        os.remove(tar_path)

    def test_no_root_archive(self):
        tar_path = "/tmp/source.tar.gz"
        nb_files = self._create_archive_no_root_dir(tar_path)

        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            rules_path = os.path.join(self.tmpdirname, str(self.source.pk), "rules")

            with open(tar_path, "rb") as f:
                self.source.handle_rules_in_tar(f)

            # listdir: list files not recursively
            extracted_files_nb = len(os.listdir(rules_path))
            self.assertEqual(nb_files, extracted_files_nb)

        os.remove(tar_path)

    def test_good_archive_rules_dir_pass(self):
        tar_path = "/tmp/source.tar.gz"
        nb_files = self._create_archive_good(tar_path, rules_dir=True)

        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            rules_path = os.path.join(self.tmpdirname, str(self.source.pk), "rules")

            with open(tar_path, "rb") as f:
                self.source.handle_rules_in_tar(f)

            # listdir: list files not recursively
            extracted_files_nb = len(os.listdir(rules_path))
            self.assertEqual(nb_files, extracted_files_nb)

        os.remove(tar_path)

    def test_good_archive_no_rules_dir_pass(self):
        tar_path = "/tmp/source.tar.gz"
        nb_files = self._create_archive_good(tar_path, rules_dir=False)

        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            rules_path = os.path.join(self.tmpdirname, str(self.source.pk), "rules")

            with open(tar_path, "rb") as f:
                self.source.handle_rules_in_tar(f)

            # listdir: list files not recursively
            extracted_files_nb = len(os.listdir(rules_path))
            self.assertEqual(nb_files, extracted_files_nb)

        os.remove(tar_path)

    def test_good_archive_no_rules_dir_fail_categories(self):
        tar_path = "/tmp/source.tar.gz"
        self._create_archive_good(tar_path, categories_fail=True)

        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            exception = None
            with open(tar_path, "rb") as f:
                try:
                    self.source.handle_rules_in_tar(f)
                except InvalidCategoryException as exc:
                    exception = exc
                finally:
                    self.assertIsNotNone(exception)

        os.remove(tar_path)

    def test_good_archive_no_rules_dir_fail_list(self):
        tar_path = "/tmp/source.tar.gz"
        self._create_archive_good(tar_path, rules_dir=False, list_fail=True)

        with self.settings(GIT_SOURCES_BASE_DIRECTORY=self.tmpdirname):
            exception = None
            with open(tar_path, "rb") as f:
                try:
                    self.source.handle_rules_in_tar(f)
                except InvalidCategoryException as exc:
                    exception = exc
                finally:
                    self.assertIsNotNone(exception)

        os.remove(tar_path)


class RestAPISourceTestCase(RestAPITestBase, APITestCase):
    def setUp(self):
        RestAPITestBase.setUp(self)
        APITestCase.setUp(self)

        self.ruleset = Ruleset.objects.create(
            name="test ruleset", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
        )
        self.ruleset.save()

    def _create_public_source(self):
        params = {
            "name": "sonic test public source",
            "comment": "MyPublicComment",
            "public_source": "oisf/trafficid",
        }
        self.http_post(reverse("publicsource-list"), params, status=status.HTTP_201_CREATED)
        sources = Source.objects.filter(name="sonic test public source")
        self.assertEqual(sources.count() == 1, True)

        self.public_source = sources.first()
        self.ruleset.sources.add(sources.first())

    def _create_custom_source(self, method, datatype, **kwargs):
        params = {
            "name": "sonic test custom source",
            "comment": "MyCustomComment",
            "method": method,
            "datatype": datatype,
        }
        params.update(kwargs)
        self.http_post(reverse("source-list"), params, status=status.HTTP_201_CREATED)
        sources = Source.objects.filter(name="sonic test custom source")
        self.assertEqual(sources.count() == 1, True)

        self.source = sources.first()
        self.ruleset.sources.add(sources.first())

    def _set_source_from_name(self, name):
        sources = Source.objects.filter(name=name)
        self.assertEqual(sources.count(), 1)
        self.source = sources[0]

    # def test_000_custom_source_iprep(self):
    #     self._create_custom_source('http', 'sigs', uri=ET_URL, cert_verif=True, use_iprep=False)
    #     response = self.http_get(reverse('source-list'))
    #     self.assertIn('results', response)

    #     results = response.get('results', [])
    #     self.assertIn('use_iprep', results[0])
    #     self.assertEqual(results[0]['use_iprep'], False)

    #     self.source.update()
    #     category = self.source.category_set.get(name='botcc')
    #     rules = category.rule_set.filter(msg__contains='ET CNC Feodo Tracker Reported CnC Server group')

    #     size = rules.count()
    #     self.assertGreater(size, 1)
    #     for rule in rules:
    #         self.assertIn('group', rule.msg)

    #     response = self.http_patch(reverse('source-detail', args=(self.source.pk,)), {'use_iprep': True, 'version': 1})
    #     self.assertEqual(response['use_iprep'], True)

    #     self._set_source_from_name('sonic test custom source')
    #     self.source.update()
    #     category = self.source.category_set.get(name='botcc')
    #     rules = category.rule_set.filter(msg__contains='ET CNC Feodo Tracker Reported CnC Server')
    #     self.assertEqual(rules.count(), 1)
    #     self.assertIn('iprep', rules[0].ruleatversion_set.first().content)

    #     response = self.http_patch(reverse('source-detail', args=(self.source.pk,)), {'use_iprep': False, 'version': 1})
    #     self.assertEqual(response['use_iprep'], False)

    #     self._set_source_from_name('sonic test custom source')
    #     self.source.update()
    #     category = self.source.category_set.get(name='botcc')
    #     rules = category.rule_set.filter(msg__contains='ET CNC Feodo Tracker Reported CnC Server')
    #     self.assertEqual(size, rules.count())

    def test_001_public_source(self):
        self._create_public_source()
        response = self.http_get(reverse("publicsource-fetch-list-sources"))
        self.assertDictEqual(response, {"fetch": "ok"})

        self.public_source.update()

        # behavior/status could be different on remote and local build
        test_results = self.public_source.test()

        if test_results["status"] is True:
            self.http_get(reverse("publicsource-list-sources"))
        else:
            self.assertTrue("errors" in test_results)

        response = self.http_delete(
            reverse("publicsource-detail", args=(self.public_source.pk,)), status=status.HTTP_204_NO_CONTENT
        )
        sources = Source.objects.filter(pk=self.public_source.pk)
        self.assertEqual(sources.count(), 0)

    def test_002_custom_source_upload(self):
        from io import BytesIO

        self._create_custom_source("local", "sig")
        self.source.new_uploaded_file(BytesIO(RULE_CONTENT.encode("utf-8")))

        self.http_post(reverse("source-update-source", args=(self.source.pk,)), status=status.HTTP_400_BAD_REQUEST)

        response = self.http_get(reverse("category-list") + "?source=%i" % self.source.pk)
        categories = response.get("results", [])
        self.assertEqual(len(categories), 1)

        response = self.http_get(reverse("rule-list") + "?category=%i" % categories[0]["pk"])
        rules = response.get("results", [])
        self.assertEqual(len(rules), 1)

        rule = rules[0]

        self.assertDictContainsSubset(
            {
                "sid": 2100498,
                "msg": "Unicode test rule éàç",  # ignore_utf8_check: 233 224 231
            },
            rule,
        )

        self.assertDictContainsSubset(
            {"state": True, "commented_in_source": False, "content": RULE_CONTENT, "rev": 7}, rule["versions"][0]
        )

    def test_003_custom_source_bad_upload(self):
        self._create_custom_source("local", "sigs")

        with (
            open("/usr/bin/find", "rb") as f,
            patch.object(
                UploadEditSourceTaskSerializer,
                "spawn",
                return_value=HttpResponse('{"status": "OK", "code": 200, "message": null, "data": {"task_pk": 123}'),
            ),
        ):
            self.http_post(reverse("source-upload", args=(self.source.pk,)), {"file": f}, format="multipart")
            try:
                self.source.new_uploaded_file(f)
            except Exception as e:
                self.assertTrue("Invalid tar file" in str(e))

        self.http_delete(reverse("source-detail", args=(self.source.pk,)), status=status.HTTP_204_NO_CONTENT)
        sources = Source.objects.filter(pk=self.source.pk)
        self.assertEqual(sources.count(), 0)

    def test_004_custom_source_http(self):
        self._create_custom_source("http", "sigs", uri=ET_URL, cert_verif=True)
        self.source.update()

    def test_005_custom_source_bad_http(self):
        self._create_custom_source("http", "sigs", uri="http://0.0.0.0:1234/")

        try:
            self.source.update()
        except OSError as e:
            self.assertTrue("Connection refused" in str(e))

    def test_006_custom_source_delete(self):
        self._create_custom_source("local", "sig")
        self.http_delete(
            reverse("source-detail", args=(self.source.pk,)),
            {"comment": "source delete"},
            status=status.HTTP_204_NO_CONTENT,
        )

        ua = UserAction.objects.order_by("pk").last()
        self.assertEqual(ua.action_type, "delete_source")
        self.assertEqual(ua.comment, "source delete")

    def test_007_source_name_unicode(self):
        self._create_public_source()

        unic = 'é&"_è-àç'  # ignore_utf8_check: 233 232 231 224
        response = self.http_patch(reverse("publicsource-detail", args=(self.public_source.pk,)), {"name": unic})
        self.assertEqual(response["name"], unic)
