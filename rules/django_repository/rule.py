from abc import ABC, abstractmethod

from django.db.models import QuerySet

from rules.models.model import Rule


class RuleRepositoryIterface(ABC):
    @abstractmethod
    def rules(
        self,
        sids: list[int] | None = None,
        query: str = "",
        *,
        with_rule_at_version: bool = False,
        with_categories: bool = False,
        with_sources: bool = False,
    ) -> QuerySet[Rule]:
        pass


class RuleRepository(RuleRepositoryIterface):
    def rules(
        self,
        sids: list[int] | None = None,
        query: str = "",
        *,
        with_rule_at_version: bool = False,
        with_categories: bool = False,
        with_sources: bool = False,
        with_ruleset: bool = False,
    ) -> QuerySet[Rule]:
        qs = Rule.objects.none()
        if sids:
            qs = Rule.objects.filter(sid__in=sids)
        if query:
            qs = Rule.objects.filter(msg__icontains=query)
        if with_categories:
            qs = qs.select_related("category")
        if with_sources:
            qs = qs.select_related("category__source")
        if with_rule_at_version:
            qs = qs.prefetch_related("ruleatversion_set")
        if with_ruleset:
            qs = qs.prefetch_related("category__source__ruleset_set")
        return qs.order_by("sid")
