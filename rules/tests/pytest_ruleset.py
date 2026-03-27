from django.utils import timezone

from rules.models.model import Ruleset, RuleProcessingFilter


def test_001_delete_ruleset_with_single_policies(db):
    # ruleset1 will have a single policy
    ruleset1 = Ruleset.objects.create(
        name="test ruleset1", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
    )
    ruleset1.save()
    ruleset2 = Ruleset.objects.create(
        name="test ruleset2", descr="descr", created_date=timezone.now(), updated_date=timezone.now()
    )
    ruleset2.save()
    # single policy
    policy1 = RuleProcessingFilter.objects.create(action="test rpf1", index=1)
    policy1.rulesets.add(ruleset1.pk)
    policy1.save()
    # non single policies
    policy2 = RuleProcessingFilter.objects.create(action="test rpf2", index=2)
    policy2.rulesets.add(ruleset1.pk, ruleset2.pk)
    policy2.save()
    policy3 = RuleProcessingFilter.objects.create(action="test rpf3", index=3)
    policy3.rulesets.add(ruleset1.pk, ruleset2.pk)
    policy3.save()

    # check get_single_policies() returns the correct number of results
    p = ruleset1.get_single_policies()
    assert len(p) == 1
    assert p[0].pk == policy1.pk
    assert len(ruleset2.get_single_policies()) == 0

    # check delete
    id_single_policy = policy1.pk
    ruleset1.delete()
    p = RuleProcessingFilter.objects.filter(pk=id_single_policy)
    assert not p.exists()

    # check if there is no gap in policy indexes
    indexes = list(RuleProcessingFilter.objects.order_by("index").values_list("index", flat=True))
    assert indexes == [0, 1]
