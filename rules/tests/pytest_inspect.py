import builtins
import sys
import inspect
import pytest
import structlog
from django.urls import URLPattern, URLResolver

from django.conf import settings
from django.urls import reverse
from django.db import models
from django.utils import timezone
from rest_framework import mixins, status

from scirius.rest_api import router
from rules.urls import urlpatterns


logger = structlog.get_logger()
extra_blacklist = {}
MIDDLEWARE = __import__(settings.RULESET_MIDDLEWARE)
try:
    extra_blacklist = MIDDLEWARE.tests.pytest_inspect.BLACKLIST
except builtins.BaseException:
    logger.info("No additional blacklist", middleware=settings.RULESET_MIDDLEWARE)
BLACKLIST = {
    "rules.views.misc": ("index", "elasticsearch", "info", "history"),
    "rules.views.task": ("status",),
    "rules.views.ruleset": ("edit_ruleset",),
    **extra_blacklist,
}

REQUIRED_DECORATORS = ("@permission_required", "@tasks_permission_required", "@check_report_perms")


def get_all_views(url_list, prefix=""):
    """Utility function to flatten URLs (handle include()"""
    views = []
    for entry in url_list:
        if isinstance(entry, URLPattern):
            views.append(entry)
        elif isinstance(entry, URLResolver):
            views.extend(get_all_views(entry.url_patterns))
    return views


@pytest.mark.parametrize("url_pattern", get_all_views(urlpatterns))
def test_view_has_permissions(url_pattern):
    """
    Dynamic audit: check each view has a permission decorator
    """
    try:
        # For simple functions or class view
        callback = url_pattern.callback
        module_name = callback.__module__
        view_name = callback.__name__
    except AttributeError:
        pytest.skip("No callback found (Admin or special route)")

    # 1. Check in blacklist
    if view_name in BLACKLIST.get(module_name, {}):
        pytest.skip(f"View {view_name} is blacklisted")

    # 2. Get View object
    view_obj = getattr(sys.modules[module_name], view_name)
    is_class = inspect.isclass(view_obj)

    found = False

    if not is_class:
        # For functions: analyze source code
        source = inspect.getsource(view_obj)
        # take only what is before the function
        def_index = source.find("def ")
        header = source[:def_index]

        for decorator in REQUIRED_DECORATORS:
            if decorator in header:
                found = True
                break
    else:
        # For classes: check check_permissions method
        # ensure the methode is not just inherited from a generic class
        if hasattr(view_obj, "check_permissions") and view_obj.check_permissions.__module__ == module_name:
            found = True

        # ViewSets (DRF) are not working the same, they use permission_classes
        if hasattr(view_obj, "permission_classes") and view_obj.permission_classes:
            found = True

    assert found, f'Security Audit Failed: Permission decorator not found on "{module_name}.{view_name}"'


# Dynamic generation of the viewsets to test
viewset_params = [(url, viewset, view_name) for url, viewset, view_name in router.registry]


@pytest.mark.parametrize("url, viewset, view_name", viewset_params)
class TestRestAPIStructure:
    """Automatic audit of DRF viewset structure"""

    def test_ordering_requirement(self, url, viewset, view_name):
        """Check we will not break pagination (ordering)"""
        v = viewset()
        # Simulate a query for dynamic QUerySets
        v.request = None

        # Only check view of List type that did not disable the test
        if not issubclass(viewset, mixins.ListModelMixin) or not getattr(viewset, "ordering_test", True):
            pytest.skip("Not a list view or ordering test disabled")

        # Check if the queryset is already sorted
        try:
            is_ordered = v.get_queryset().ordered
        except Exception:
            is_ordered = False

        if not is_ordered:
            err = f'Viewset "{viewset.__name__}" must set an "ordering" attribute'
            assert hasattr(viewset, "ordering"), err
            assert len(viewset.ordering) > 0, err

    def test_list_access(self, drf, url, viewset, view_name):
        """Check all list endpoints are responding with an HTTP 200"""
        if not issubclass(viewset, mixins.ListModelMixin):
            pytest.skip("Not a list view")

        target_url = reverse(f"{view_name}-list")
        if view_name.startswith("threat"):
            target_url += "?event_view=false"

        response = drf.get(target_url)
        assert response.status_code == status.HTTP_200_OK

    def test_ordering_fields(self, drf, url, viewset, view_name):
        """Check defined sorted fields"""
        if not hasattr(viewset, "ordering_fields") or viewset.ordering_fields == "__all__":
            pytest.skip("No specific ordering fields")

        for field in viewset.ordering_fields:
            target_url = reverse(f"{view_name}-list") + f"?ordering={field}"
            response = drf.get(target_url)
            assert response.status_code == status.HTTP_200_OK

    def test_filter_fields(self, drf, url, viewset, view_name):
        """Check defined filters (DateTime, Choices, etc.)"""
        if not hasattr(viewset, "filterset_fields"):
            pytest.skip("No filters defined")

        v = viewset()
        model = v.get_queryset().model

        for field in viewset.filterset_fields:
            if "__" in field:
                continue  # On saute les lookups complexes

            field_obj = model._meta.get_field(field)
            if field_obj.is_relation:
                continue

            param = "0"
            if isinstance(field_obj, models.DateTimeField):
                param = timezone.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            elif getattr(field_obj, "choices", None):
                param = field_obj.choices[0][0]

            target_url = reverse(f"{view_name}-list") + f"?{field}={param}"
            response = drf.get(target_url)
            assert response.status_code == status.HTTP_200_OK

    def test_search_functionality(self, drf, url, viewset, view_name):
        """Check if the search when search_field is present"""
        if not hasattr(viewset, "search_fields") or view_name.startswith("threat"):
            pytest.skip("No search fields")

        target_url = reverse(f"{view_name}-list") + "?search=test"
        response = drf.get(target_url)
        assert response.status_code == status.HTTP_200_OK

    def test_has_docstring(self, url, viewset, view_name):
        assert viewset.__doc__ is not None, f"Viewset {view_name} lacks a docstring"
