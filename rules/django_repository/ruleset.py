from django.db.models import QuerySet

from rules.models.model import Ruleset, RulesetTransformation


class RulesetRepository:
    def list_transformations(
        self,
        ruleset: Ruleset,
        *,
        key: str | None = None,
        value: str | None = None,
    ) -> QuerySet[RulesetTransformation]:
        qs = RulesetTransformation.objects.filter(ruleset_transformation=ruleset)
        if key is not None:
            qs = qs.filter(key=key)
        if value is not None:
            qs = qs.filter(value=value)
        return qs

    def get_transformation(self, ruleset: Ruleset, key: str) -> RulesetTransformation | None:
        return RulesetTransformation.objects.filter(ruleset_transformation=ruleset, key=key).first()
