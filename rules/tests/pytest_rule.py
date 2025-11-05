from rules.django_repository import rule


def test_repository_rule_list(db):
    repo = rule.RuleRepository()
    repo.rules([1, 2, 3])
    repo.rules([1, 2, 3], with_rule_at_version=True)
    repo.rules([1, 2, 3], with_categories=True)
    repo.rules([1, 2, 3], with_rule_at_version=True, with_categories=True)
