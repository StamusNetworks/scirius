import os
import pytest
import tarfile
import tempfile
from pathlib import Path
from shutil import rmtree
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.utils import timezone

from rules.api.source import SourceSerializer
from rules.models.model import (
    InvalidCategoryException,
    Rule,
    Source,
)

if TYPE_CHECKING:
    from rules.models.model import IoCMeta


ET_URL = "https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz"

RULE_CONTENT = 'alert ip any any -> any any (msg:"Unicode test rule éàç"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)\n'  # ignore_utf8_check: 233 224 231


@pytest.fixture
def source(db, settings, tmp_path) -> Source:
    settings.GIT_SOURCES_BASE_DIRECTORY = str(tmp_path)
    return Source.objects.create(
        name="ET Open", method="http", datatype="sigs", uri=ET_URL, created_date=timezone.now()
    )


def _create_archive_good(tar_path: str, rules_dir: bool = True, categories_fail: bool = False, list_fail: bool = False):
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


def _create_archive_no_root_dir(tar_path):
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


def _create_archive_files_different_levels(tar_path: str):
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


def _create_archive_files_dot_prefix(tar_path: str, different_levels: bool = False):
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


# def test_source_update(source: Source):
#     """Test source update"""
#     source.update()
#     assert Category.objects.filter(source=source).count() != 0


def test_unicode_rule(db, tmp_path):
    source = Source.objects.create(name="Unicode rule", method="local", datatype="sig", created_date=timezone.now())

    with Path(tmp_path / "unicode_rule.txt").open("wb") as f:
        f.write(RULE_CONTENT.encode("utf-8"))
        f.seek(0)
        source.handle_rules_file(f)
        assert Rule.objects.count() == 1


def test_source_name_depending_on_datatype(db):
    source = Source(name="Unicode rule", method="local", datatype="sig", created_date=timezone.now())
    source.clean()

    source.name = "some/source with sp&cial chars '"
    source.clean()

    source.datatype = "ioc"
    pytest.raises(ValidationError, source.clean)
    source.datatype = "other"
    pytest.raises(ValidationError, source.clean)
    source.datatype = "b64dataset"
    pytest.raises(ValidationError, source.clean)

    source.name = "/tmp/oops-I-did-it-again"  # noqa: S108
    pytest.raises(ValidationError, source.clean)
    source.name = "I'm-sorry"
    pytest.raises(ValidationError, source.clean)

    source.name = "ok-source"
    source.clean()


@pytest.mark.parametrize(
    "create_fn,kwargs",
    [
        (_create_archive_files_dot_prefix, {}),
        (_create_archive_files_dot_prefix, {"different_levels": True}),
        (_create_archive_files_different_levels, {}),
        (_create_archive_no_root_dir, {}),
        (_create_archive_good, {"rules_dir": True}),
        (_create_archive_good, {"rules_dir": False}),
    ],
    ids=[
        "dot_prefix",
        "dot_prefix_different_levels",
        "different_levels",
        "no_root_dir",
        "good_rules_dir",
        "good_no_rules_dir",
    ],
)
def test_archive_extraction(source: Source, tmp_path, create_fn, kwargs):
    tar_path = tmp_path / "source.tar.gz"
    nb_files = create_fn(str(tar_path), **kwargs)
    rules_path = tmp_path / str(source.pk) / "rules"

    with tar_path.open("rb") as f:
        source.handle_rules_in_tar(f)

    extracted_files_nb = sum(1 for _ in rules_path.iterdir())
    assert nb_files == extracted_files_nb


@pytest.mark.parametrize(
    "kwargs",
    [
        {"categories_fail": True},
        {"rules_dir": False, "list_fail": True},
    ],
    ids=["fail_categories", "fail_list"],
)
def test_archive_invalid_category(source: Source, tmp_path, kwargs):
    tar_path = tmp_path / "source.tar.gz"
    _create_archive_good(str(tar_path), **kwargs)

    with tar_path.open("rb") as f, pytest.raises(InvalidCategoryException):
        source.handle_rules_in_tar(f)


def test_rest_serializer_bad_ioc(db):
    source = {
        "name": "test-rest-ioc",
        "method": "local",
        "datatype": "ioc",
    }

    # ioc without ioc_type
    serializer = SourceSerializer(data=source)
    assert not serializer.is_valid()

    # ioc without metadata
    source["ioc_type"] = "hostname"
    serializer = SourceSerializer(data=source)
    assert not serializer.is_valid()

    # ioc with empty metadata
    source["metadata"] = []
    serializer = SourceSerializer(data=source)
    assert not serializer.is_valid()

    # ioc with metadata without ioc_type
    source.pop("ioc_type")
    serializer = SourceSerializer(data=source)
    assert not serializer.is_valid()

    # everything but empty metadata
    source["ioc_type"] = "hostname"
    serializer = SourceSerializer(data=source)
    assert not serializer.is_valid()


def test_rest_serializer_save_ioc(db):
    source = {
        "name": "test-rest-ioc",
        "method": "local",
        "datatype": "ioc",
        "ioc_type": "hostname",
        "metadata": [{"key": "the-key", "value": "it.works"}],
    }

    # create
    serializer = SourceSerializer(data=source)
    assert serializer.is_valid(raise_exception=True)
    instance: Source = serializer.save()
    pk = instance.pk
    assert pk is not None
    assert instance.name == "test-rest-ioc"
    assert instance.method == "local"
    assert instance.datatype == "ioc"
    assert instance.ioc_type == "hostname"
    assert instance.ioc_meta.count() == 1
    ioc: IoCMeta = instance.ioc_meta.first()
    assert ioc.key == "the-key"
    assert ioc.value == "it.works"

    # partial update
    serializer = SourceSerializer(
        instance=instance,
        partial=True,
        data={"metadata": [{"key": "k1", "value": "v1"}, {"key": "k2", "value": "v2"}]},
    )
    assert serializer.is_valid(raise_exception=True)
    instance: Source = serializer.save()
    assert instance.pk == pk
    assert instance.name == "test-rest-ioc"
    assert instance.method == "local"
    assert instance.datatype == "ioc"
    assert instance.ioc_type == "hostname"
    assert instance.ioc_meta.count() == 2
    ioc: IoCMeta = instance.ioc_meta.all()
    assert ioc[0].key == "k1"
    assert ioc[0].value == "v1"
    assert ioc[1].key == "k2"
    assert ioc[1].value == "v2"

    # wrong partial update by emptying metadata
    serializer = SourceSerializer(
        instance=instance,
        partial=True,
        data={"metadata": []},
    )
    assert not serializer.is_valid()


def test_rest_serializer_update(db):
    source = {
        "name": "test-rest-ioc",
        "method": "local",
        "datatype": "sig",
        "ioc_type": "hostname",
    }

    serializer = SourceSerializer(data=source)
    assert not serializer.is_valid()

    source["metadata"] = [{"key": "the-key", "value": "it.works"}]
    serializer = SourceSerializer(data=source)
    assert not serializer.is_valid()

    source.pop("ioc_type")
    serializer = SourceSerializer(data=source)
    assert not serializer.is_valid()

    source.pop("metadata")
    serializer = SourceSerializer(data=source)
    assert serializer.is_valid()


def test_rest_serializer_ioc_representation(db):
    source = {
        "name": "test-rest-ioc",
        "method": "local",
        "datatype": "ioc",
        "ioc_type": "hostname",
        "metadata": [{"key": "the-key", "value": "it.works"}],
    }
    serializer = SourceSerializer(data=source)
    assert serializer.is_valid()
    instance = serializer.save()
    representation = SourceSerializer().to_representation(instance=instance)
    assert representation["pk"] > 0
    assert representation["name"] == source["name"]
    assert representation["method"] == source["method"]
    assert representation["datatype"] == source["datatype"]
    assert representation["ioc_type"] == source["ioc_type"]
    assert representation["metadata"] == source["metadata"]
