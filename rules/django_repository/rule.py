from abc import ABC, abstractmethod
from typing import Iterable

from rules.models.model import Rule


class RuleRepositoryIterface(ABC):
    @abstractmethod
    def rules(
        self, sids: list[int], with_rule_at_version: bool = False, with_categories: bool = False
    ) -> Iterable[Rule]:
        pass


class RuleRepository(RuleRepositoryIterface):
    def rules(
        self, sids: list[int], with_rule_at_version: bool = False, with_categories: bool = False
    ) -> Iterable[Rule]:
        qs = Rule.objects.filter(sid__in=sids)
        if with_categories:
            qs = qs.select_related("category")
        if with_rule_at_version:
            qs = qs.prefetch_related("ruleatversion_set")
        return qs.order_by("sid").iterator(chunk_size=128)
