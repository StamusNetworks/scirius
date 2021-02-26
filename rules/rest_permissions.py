from functools import wraps

from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

from scirius.utils import get_middleware_module


def has_group_permission(perms, owner_allowed=False):
    def decorator(func):
        # allows to disable permissions check on the class
        # check method permissions instead of class permissions
        func.disable_main_check = True

        # allows to use drf action decorator with this one
        @wraps(func)
        def view(self, request, *args, **kwargs):
            # specific case for accounts module
            # current user can edit his own content
            if owner_allowed and self.__class__.__name__ == 'AccountViewSet':
                modified_user_pk = int(kwargs.get('pk', '-1'))
                if request.user.sciriususer.pk == modified_user_pk:
                    return func(self, request, *args, **kwargs)

            if not HasGroupPermission.check_perms(request, self, perms):
                raise PermissionDenied()
            return func(self, request, *args, **kwargs)
        return view
    return decorator


class NoPermission(BasePermission):
    def has_permission(self, request, view):
        return False


class HasGroupPermission(BasePermission):
    """
    Ensure user is in required groups.
    """
    READ = ('GET', 'HEAD', 'OPTIONS')
    WRITE = ('POST', 'PUT', 'PATCH', 'DELETE')

    def has_permission(self, request, view):
        # if method is decorated, we skip the main class check
        if getattr(view, 'action', False):
            func = getattr(view, view.action)
            if hasattr(func, 'disable_main_check') and func.disable_main_check:
                return True

        required_groups_mapping = getattr(view, "REQUIRED_GROUPS", {})
        action = None
        if request.method in HasGroupPermission.READ:
            action = 'READ'
        elif request.method in HasGroupPermission.WRITE:
            action = 'WRITE'
        else:
            raise Exception('Not implemented: {}'.format(request.method))

        required_groups = required_groups_mapping.get(action, [])

        return self.check_perms(request, view, required_groups)

    @staticmethod
    def check_perms(request, view, required_groups):
        if request.user.is_anonymous:
            return False

        if get_middleware_module('common').has_multitenant():
            # bypass tenant check on some ViewSet that does not handle tenants
            if not getattr(view, 'no_tenant_check', False):
                if {'rules.events_view', 'rules.events_edit'} & set(required_groups):
                    tenant = request.query_params.get('tenant', -1)
                    try:
                        tenant = int(tenant)
                    except (ValueError, TypeError):
                        return False

                    if tenant in (-1, 0):
                        if not request.user.sciriususer.has_no_tenant():
                            return False
                    elif tenant > 0:
                        if not request.user.sciriususer.has_all_tenants():
                            if tenant not in request.user.sciriususer.get_tenants().values_list('pk', flat=True):
                                return False

        for group in required_groups:
            if request.user.has_perm(group):
                return True
        return False
