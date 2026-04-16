from django.db.models import QuerySet

from rules.models.model import Category, CategoryTransformation, Ruleset


class CategoryRepository:
    def list_transformations(
        self,
        ruleset: Ruleset,
        *,
        key: str | None = None,
        value: str | None = None,
    ) -> QuerySet[CategoryTransformation]:
        qs = CategoryTransformation.objects.filter(ruleset=ruleset)
        if key is not None:
            qs = qs.filter(key=key)
        if value is not None:
            qs = qs.filter(value=value)
        return qs

    def get_transformation(self, category: Category, ruleset: Ruleset, key: str) -> CategoryTransformation | None:
        return CategoryTransformation.objects.filter(
            ruleset=ruleset, category_transformation=category, key=key
        ).first()

    def delete_transformation(self, category: Category, ruleset: Ruleset, key: str) -> None:
        CategoryTransformation.objects.filter(
            ruleset=ruleset, category_transformation=category, key=key
        ).delete()

    def transformation_exists(self, ruleset: Ruleset, category: Category, key: str, value: str) -> bool:
        return CategoryTransformation.objects.filter(
            ruleset=ruleset,
            category_transformation=category,
            key=key,
            value=value,
        ).exists()
