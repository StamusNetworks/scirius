from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rules.django_repository.category import CategoryRepository
from rules.django_repository.rule import RuleRepository
from rules.django_repository.ruleset import RulesetRepository
from rules.models.model import (
    Category,
    CategoryTransformation,
    Rule,
    RuleTransformation,
    Ruleset,
    Transformation,
    UserAction,
)

if TYPE_CHECKING:
    from django.contrib.auth.models import User

# Maps a Transformation.Type key to the matching enum class and "NONE" sentinel.
_TYPE_MAP = {
    Transformation.ACTION: Transformation.ActionTransfoType,
    Transformation.LATERAL: Transformation.LateralTransfoType,
    Transformation.TARGET: Transformation.TargetTransfoType,
}
_NONE_MAP = {
    Transformation.ACTION: Transformation.A_NONE,
    Transformation.LATERAL: Transformation.L_NO,
    Transformation.TARGET: Transformation.T_NONE,
}


class TransformationService:
    def __init__(
        self,
        category_repo: CategoryRepository | None = None,
        ruleset_repo: RulesetRepository | None = None,
        rule_repo: RuleRepository | None = None,
    ) -> None:
        self._category_repo = category_repo or CategoryRepository()
        self._ruleset_repo = ruleset_repo or RulesetRepository()
        self._rule_repo = rule_repo or RuleRepository()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_type(self, key: Transformation.Type) -> type:
        if key not in _TYPE_MAP:
            raise Exception(f"Key '{key}' is unknown")
        return _TYPE_MAP[key]

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def validate_key_value(self, key: str | None, value: str | None) -> None:
        """Raise ValueError when the (key, value) pair is not a valid transformation."""
        if key not in Transformation.AVAILABLE_MODEL_TRANSFO:
            raise ValueError({"transfo_type": [f'"{key}" is not a valid choice.']})
        if value not in Transformation.AVAILABLE_MODEL_TRANSFO[key]:
            raise ValueError({"transfo_value": [f'"{value}" is not a valid choice.']})

    def validate_rule_choices(self, rule: Rule, transfo_type: Transformation.Type, value: str) -> None:
        """Raise ValueError when value is not an allowed choice for this specific rule."""
        choices = [choice[0] for choice in rule.get_transformation_choices(transfo_type)]
        if value not in choices:
            raise ValueError({"transfo_value": [f'"{value}" is not a valid choice.']})

    def validate_transformation_filter(self, query_params: dict[str, Any]) -> tuple[str, str]:
        """
        Validate query parameters for the GET /rule/transformation/ endpoint.

        Returns ``(key_str, value_str)`` on success; raises ValueError otherwise.
        """
        params = dict(query_params)
        key_str = params.pop("transfo_type", None)
        value_str = params.pop("transfo_value", None)

        errors: dict[str, list[str]] = {}
        if key_str is None:
            errors["transfo_type"] = ["This field is required."]
        if value_str is None:
            errors["transfo_value"] = ["This field is required."]
        if errors:
            raise ValueError(errors)

        if params:
            raise ValueError(
                {"filters": ['Wrong filters: "{}"'.format(", ".join(params.keys()))]}
            )

        if key_str not in Transformation.AVAILABLE_MODEL_TRANSFO:
            raise ValueError({"filters": [f'Wrong filter type "{key_str}".']})

        if value_str not in Transformation.AVAILABLE_MODEL_TRANSFO[key_str]:
            raise ValueError(
                {"filters": [f'Wrong filter value "{value_str}" for key "{key_str}".']}
            )

        return key_str, value_str

    # ------------------------------------------------------------------
    # Read operations  (replaces Transformable.get_transformation / is_transformed)
    # ------------------------------------------------------------------

    def get_for_ruleset(
        self,
        ruleset: Ruleset,
        key: Transformation.Type,
    ) -> Any | None:
        """
        Return the effective transformation value for a ruleset, or None.

        The "NONE" sentinels (A_NONE, L_NO, T_NONE) are treated as "no transformation"
        and return None, matching the original Ruleset.get_transformation behaviour.
        """
        TYPE = self._resolve_type(key)
        NONE = _NONE_MAP[key]
        row = self._ruleset_repo.get_transformation(ruleset, key.value)
        if row is not None and row.value != NONE.value:
            return TYPE(row.value)
        return None

    def get_for_category(
        self,
        category: Category,
        ruleset: Ruleset,
        key: Transformation.Type,
        *,
        override: bool = False,
    ) -> Any | None:
        """
        Return the effective transformation value for a category.

        If ``override=True`` and no category-level row exists, falls back to the
        ruleset-level transformation (via :meth:`get_for_ruleset`).

        Respects the in-memory ``Category.TRANSFORMATIONS`` cache when active.
        """
        TYPE = self._resolve_type(key)

        if Category.TRANSFORMATIONS == {}:
            # DB path
            row = self._category_repo.get_transformation(category, ruleset, key.value)
            if row is not None:
                return TYPE(row.value)
            if override:
                return self.get_for_ruleset(ruleset, key)
        else:
            # Cache path (Category.enable_cache() was called)
            category_str = Category.__name__.lower()
            ruleset_str = Ruleset.__name__.lower()
            for trans, tsets in Category.TRANSFORMATIONS[key][category_str].items():
                if category.pk in tsets:
                    return trans
            if override:
                for trans, tsets in Category.TRANSFORMATIONS[key][ruleset_str].items():
                    if tsets and ruleset.pk in tsets:
                        return trans

        return None

    def _get_for_rule_from_cache(
        self, rule: Rule, ruleset: Ruleset, key: Transformation.Type, override: bool
    ) -> Any | None:
        """Cache-path implementation for :meth:`get_for_rule` (Rule.TRANSFORMATIONS is active)."""
        rule_str = Rule.__name__.lower()
        for trans, tsets in Rule.TRANSFORMATIONS[key][rule_str].items():
            if tsets is not None and tsets and rule.pk in tsets:
                return trans
        if override:
            category_str = Category.__name__.lower()
            ruleset_str = Ruleset.__name__.lower()
            for trans, tsets in Rule.TRANSFORMATIONS[key][category_str].items():
                if tsets is not None and tsets and rule.category.pk in tsets:
                    return trans
            for trans, tsets in Rule.TRANSFORMATIONS[key][ruleset_str].items():
                if tsets is not None and tsets and ruleset.pk in tsets:
                    return trans
        return None

    def get_for_rule(
        self,
        rule: Rule,
        ruleset: Ruleset,
        key: Transformation.Type,
        *,
        override: bool = False,
    ) -> Any | None:
        """
        Return the effective transformation value for a rule.

        If ``override=True`` and no rule-level row exists, falls back to the
        category level and then to the ruleset level.

        Respects the in-memory ``Rule.TRANSFORMATIONS`` cache when active.
        """
        TYPE = self._resolve_type(key)

        if Rule.TRANSFORMATIONS != {}:
            return self._get_for_rule_from_cache(rule, ruleset, key, override)

        # DB path
        row = self._rule_repo.get_transformation(rule, ruleset, key.value)
        if row is not None:
            return TYPE(row.value)
        if override:
            cat_row = self._category_repo.get_transformation(rule.category, ruleset, key.value)
            if cat_row is not None:
                return TYPE(cat_row.value)
            return self.get_for_ruleset(ruleset, key)
        return None

    def is_transformed(
        self,
        obj: Category | Rule | Ruleset,
        ruleset: Ruleset | None,
        key: Transformation.Type = Transformation.ACTION,
        value: Any = Transformation.A_DROP,
    ) -> bool:
        """
        Return True when *obj* has the given transformation applied.

        Dispatches on the type of *obj*:
        - ``Category`` — checks ``CategoryTransformation`` (respects cache)
        - ``Rule``     — checks ``RuleTransformation`` (respects cache; also fixes the
                         pre-existing bug where the model compared a Rule instance against
                         a list of integers)
        - ``Ruleset``  — checks ``RulesetTransformation`` directly
        """
        if isinstance(obj, Category):
            if Category.TRANSFORMATIONS == {}:
                return CategoryTransformation.objects.filter(
                    ruleset=ruleset,
                    category_transformation=obj,
                    key=key.value,
                    value=value.value,
                ).exists()
            category_str = Category.__name__.lower()
            return obj.pk in Category.TRANSFORMATIONS[key][category_str][value]

        if isinstance(obj, Rule):
            if Rule.TRANSFORMATIONS == {}:
                return RuleTransformation.objects.filter(
                    ruleset=ruleset,
                    rule_transformation=obj,
                    key=key.value,
                    value=value.value,
                ).exists()
            rule_str = Rule.__name__.lower()
            return obj.pk in Rule.TRANSFORMATIONS[key][rule_str][value]

        # Ruleset — no cache path needed
        if isinstance(obj, Ruleset):
            return Ruleset.objects.filter(
                pk=obj.pk,
                rulesettransformation__key=key.value,
                rulesettransformation__value=value.value,
            ).exists()

        raise TypeError(f"Cannot check transformation for type {type(obj)!r}")

    def suppress_transformation(
        self,
        category: Category,
        ruleset: Ruleset,
        key: Transformation.Type,
    ) -> None:
        """Delete the CategoryTransformation row for *category* + *ruleset* + *key*."""
        self._category_repo.delete_transformation(category, ruleset, key.value)

    # ------------------------------------------------------------------
    # UserAction logging helpers
    # ------------------------------------------------------------------

    def _build_action_fields(  # noqa: PLR0913
        self,
        source: dict | object,
        fields_mapping: dict[str, str],
        action_type: str,
        user: User,
        comment: str | None,
        *,
        from_instance: bool = False,
    ) -> dict:
        fields: dict[str, Any] = dict(fields_mapping)
        for dest_key, src_key in dict(fields_mapping).items():
            fields[dest_key] = getattr(source, src_key) if from_instance else source[src_key]  # type: ignore[index]
        fields["comment"] = comment
        fields["action_type"] = action_type
        fields["user"] = user
        fields["transformation"] = "{}: {}".format(
            fields.pop("trans_type"),
            fields.pop("trans_value").title(),
        )
        return fields

    def log_create(
        self,
        validated_data: dict,
        fields_mapping: dict[str, str],
        action_type: str,
        user: User,
        comment: str | None,
    ) -> None:
        """Log a UserAction after a transformation has been created."""
        fields = self._build_action_fields(validated_data, fields_mapping, action_type, user, comment)
        UserAction.create(**fields)

    def log_update(  # noqa: PLR0913
        self,
        instance: object,
        validated_data: dict,
        fields_mapping: dict[str, str],
        action_type: str,
        user: User,
        comment: str | None,
        *,
        partial: bool,
    ) -> None:
        """Log a UserAction after a transformation has been updated."""
        fields: dict[str, Any] = dict(fields_mapping)
        for dest_key, src_key in dict(fields_mapping).items():
            if src_key in validated_data:
                fields[dest_key] = validated_data[src_key]
            elif partial:
                val = getattr(instance, src_key, None)
                if val is not None:
                    fields[dest_key] = val
        fields["comment"] = comment
        fields["action_type"] = action_type
        fields["user"] = user
        fields["transformation"] = "{}: {}".format(
            fields.pop("trans_type"),
            fields.pop("trans_value").title(),
        )
        UserAction.create(**fields)

    def log_delete(
        self,
        instance: object,
        fields_mapping: dict[str, str],
        action_type: str,
        user: User,
        comment: str | None,
    ) -> None:
        """Log a UserAction after a transformation has been deleted."""
        fields = self._build_action_fields(
            instance, fields_mapping, action_type, user, comment, from_instance=True
        )
        UserAction.create(**fields)

    # ------------------------------------------------------------------
    # Transformation list endpoint
    # ------------------------------------------------------------------

    def get_transformed_rules(self, key_str: str, value_str: str) -> dict:  # noqa: PLR0912
        """
        For each ruleset, compute the set of rule sids that are effectively
        transformed by (key_str, value_str), taking category- and ruleset-level
        inheritance into account.

        Returns ``{ruleset_pk: {"name": str, "transformation": {...}, "rules": [...], "rules_count": int}}``.
        """
        key = Transformation.Type(key_str)

        if key == Transformation.ACTION:
            value = Transformation.ActionTransfoType(value_str)
        elif key == Transformation.LATERAL:
            value = Transformation.LateralTransfoType(value_str)
        else:
            value = Transformation.TargetTransfoType(value_str)

        res: dict = {}
        try:
            Rule.enable_cache()

            for ruleset in Ruleset.objects.all():
                trans_rules = self._rule_repo.list_transformations(ruleset, key=key_str, value=value_str)
                trans_cats = self._category_repo.list_transformations(ruleset, key=key_str, value=value_str)
                trans_rulesets = self._ruleset_repo.list_transformations(ruleset, key=key_str, value=value_str)

                all_rules: set[int] = set()

                res[ruleset.pk] = {
                    "name": ruleset.name,
                    "transformation": {"transfo_key": key_str, "transfo_value": value_str},
                    "rules": [],
                }

                for trans in trans_rules:
                    all_rules.add(trans.rule_transformation.pk)

                for trans in trans_cats:
                    category = trans.category_transformation
                    for rule in category.rule_set.all():
                        rule_trans_value = self.get_for_rule(rule, ruleset, key)
                        if rule_trans_value is None or rule_trans_value == value:
                            all_rules.add(rule.sid)

                if trans_rulesets:
                    for category in ruleset.categories.all():
                        trans_cat = self._category_repo.list_for_category(ruleset, category)
                        if trans_cat.count() == 0:
                            for rule in category.rule_set.all():
                                rule_trans_value = self.get_for_rule(rule, ruleset, key)
                                if rule_trans_value is None or rule_trans_value == value:
                                    all_rules.add(rule.sid)
                        else:
                            for trans in trans_cat:
                                for rule in category.rule_set.all():
                                    rule_trans_value = self.get_for_rule(rule, ruleset, key)
                                    if trans.key == key and trans.value == value:
                                        if rule_trans_value is None or rule_trans_value == value:
                                            all_rules.add(rule.sid)
                                    else:
                                        if rule_trans_value == value:
                                            all_rules.add(rule.sid)

                res[ruleset.pk]["rules"] = list(all_rules)
                res[ruleset.pk]["rules_count"] = len(all_rules)
        finally:
            Rule.disable_cache()

        return res
