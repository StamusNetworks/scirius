"""Unit tests for transformation_exists() on CategoryRepository, RuleRepository, RulesetRepository."""
import pytest
from django.utils import timezone

from rules.django_repository.category import CategoryRepository
from rules.django_repository.rule import RuleRepository
from rules.django_repository.ruleset import RulesetRepository
from rules.models.model import (
    Category,
    CategoryTransformation,
    Rule,
    Ruleset,
    RulesetTransformation,
    RuleTransformation,
    Source,
    Transformation,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def source(db):
    return Source.objects.create(name="test-source", created_date=timezone.now(), method="local", datatype="sig")


@pytest.fixture
def category(source):
    return Category.objects.create(name="test-category", filename="test.rules", source=source)


@pytest.fixture
def rule(category):
    return Rule.objects.create(sid=1001, category=category, msg="test rule")


@pytest.fixture
def ruleset(source):
    rs = Ruleset.objects.create(name="test-ruleset", descr="", created_date=timezone.now(), updated_date=timezone.now())
    rs.sources.add(source)
    return rs


@pytest.fixture
def other_ruleset(source):
    rs = Ruleset.objects.create(
        name="other-ruleset", descr="", created_date=timezone.now(), updated_date=timezone.now()
    )
    rs.sources.add(source)
    return rs


# ---------------------------------------------------------------------------
# CategoryRepository.transformation_exists
# ---------------------------------------------------------------------------


class TestCategoryRepositoryTransformationExists:
    def test_returns_true_when_row_matches(self, category, ruleset):
        CategoryTransformation.objects.create(
            ruleset=ruleset,
            category_transformation=category,
            key=Transformation.ACTION.value,
            value=Transformation.A_DROP.value,
        )
        repo = CategoryRepository()
        assert (
            repo.transformation_exists(ruleset, category, Transformation.ACTION.value, Transformation.A_DROP.value)
            is True
        )

    def test_returns_false_when_no_row(self, category, ruleset):
        repo = CategoryRepository()
        assert (
            repo.transformation_exists(ruleset, category, Transformation.ACTION.value, Transformation.A_DROP.value)
            is False
        )

    def test_returns_false_for_wrong_key(self, category, ruleset):
        CategoryTransformation.objects.create(
            ruleset=ruleset,
            category_transformation=category,
            key=Transformation.ACTION.value,
            value=Transformation.A_DROP.value,
        )
        repo = CategoryRepository()
        assert (
            repo.transformation_exists(ruleset, category, Transformation.LATERAL.value, Transformation.A_DROP.value)
            is False
        )

    def test_returns_false_for_wrong_value(self, category, ruleset):
        CategoryTransformation.objects.create(
            ruleset=ruleset,
            category_transformation=category,
            key=Transformation.ACTION.value,
            value=Transformation.A_DROP.value,
        )
        repo = CategoryRepository()
        assert (
            repo.transformation_exists(ruleset, category, Transformation.ACTION.value, Transformation.A_REJECT.value)
            is False
        )

    def test_returns_false_for_wrong_ruleset(self, category, ruleset, other_ruleset):
        CategoryTransformation.objects.create(
            ruleset=ruleset,
            category_transformation=category,
            key=Transformation.ACTION.value,
            value=Transformation.A_DROP.value,
        )
        repo = CategoryRepository()
        assert (
            repo.transformation_exists(
                other_ruleset, category, Transformation.ACTION.value, Transformation.A_DROP.value
            )
            is False
        )


# ---------------------------------------------------------------------------
# RuleRepository.transformation_exists
# ---------------------------------------------------------------------------


class TestRuleRepositoryTransformationExists:
    def test_returns_true_when_row_matches(self, rule, ruleset):
        RuleTransformation.objects.create(
            ruleset=ruleset,
            rule_transformation=rule,
            key=Transformation.LATERAL.value,
            value=Transformation.L_YES.value,
        )
        repo = RuleRepository()
        assert (
            repo.transformation_exists(ruleset, rule, Transformation.LATERAL.value, Transformation.L_YES.value) is True
        )

    def test_returns_false_when_no_row(self, rule, ruleset):
        repo = RuleRepository()
        assert (
            repo.transformation_exists(ruleset, rule, Transformation.LATERAL.value, Transformation.L_YES.value)
            is False
        )

    def test_returns_false_for_wrong_key(self, rule, ruleset):
        RuleTransformation.objects.create(
            ruleset=ruleset,
            rule_transformation=rule,
            key=Transformation.LATERAL.value,
            value=Transformation.L_YES.value,
        )
        repo = RuleRepository()
        assert (
            repo.transformation_exists(ruleset, rule, Transformation.TARGET.value, Transformation.L_YES.value) is False
        )

    def test_returns_false_for_wrong_value(self, rule, ruleset):
        RuleTransformation.objects.create(
            ruleset=ruleset,
            rule_transformation=rule,
            key=Transformation.LATERAL.value,
            value=Transformation.L_YES.value,
        )
        repo = RuleRepository()
        assert (
            repo.transformation_exists(ruleset, rule, Transformation.LATERAL.value, Transformation.L_AUTO.value)
            is False
        )

    def test_returns_false_for_wrong_ruleset(self, rule, ruleset, other_ruleset):
        RuleTransformation.objects.create(
            ruleset=ruleset,
            rule_transformation=rule,
            key=Transformation.LATERAL.value,
            value=Transformation.L_YES.value,
        )
        repo = RuleRepository()
        assert (
            repo.transformation_exists(other_ruleset, rule, Transformation.LATERAL.value, Transformation.L_YES.value)
            is False
        )


# ---------------------------------------------------------------------------
# RulesetRepository.transformation_exists
# ---------------------------------------------------------------------------


class TestRulesetRepositoryTransformationExists:
    def test_returns_true_when_row_matches(self, ruleset):
        RulesetTransformation.objects.create(
            ruleset_transformation=ruleset,
            key=Transformation.TARGET.value,
            value=Transformation.T_SOURCE.value,
        )
        repo = RulesetRepository()
        assert (
            repo.transformation_exists(ruleset, Transformation.TARGET.value, Transformation.T_SOURCE.value) is True
        )

    def test_returns_false_when_no_row(self, ruleset):
        repo = RulesetRepository()
        assert (
            repo.transformation_exists(ruleset, Transformation.TARGET.value, Transformation.T_SOURCE.value) is False
        )

    def test_returns_false_for_wrong_key(self, ruleset):
        RulesetTransformation.objects.create(
            ruleset_transformation=ruleset,
            key=Transformation.TARGET.value,
            value=Transformation.T_SOURCE.value,
        )
        repo = RulesetRepository()
        assert (
            repo.transformation_exists(ruleset, Transformation.ACTION.value, Transformation.T_SOURCE.value) is False
        )

    def test_returns_false_for_wrong_value(self, ruleset):
        RulesetTransformation.objects.create(
            ruleset_transformation=ruleset,
            key=Transformation.TARGET.value,
            value=Transformation.T_SOURCE.value,
        )
        repo = RulesetRepository()
        assert (
            repo.transformation_exists(ruleset, Transformation.TARGET.value, Transformation.T_DESTINATION.value)
            is False
        )

    def test_returns_false_for_different_ruleset(self, ruleset, other_ruleset):
        RulesetTransformation.objects.create(
            ruleset_transformation=ruleset,
            key=Transformation.TARGET.value,
            value=Transformation.T_SOURCE.value,
        )
        repo = RulesetRepository()
        assert (
            repo.transformation_exists(other_ruleset, Transformation.TARGET.value, Transformation.T_SOURCE.value)
            is False
        )
