
from rest_framework import permissions


class IsStaffOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        # Authentication is required
        if request.user is None or not request.user.is_authenticated():
            return False

        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        return request.user.is_staff or request.user.is_superuser


class IsCurrentUserOrSuperUserOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):

        # Authentication is required
        if request.user is None or not request.user.is_authenticated():
            return False

        if request.user.is_superuser:
            return True

        if request.user.is_staff:
            if view.action == 'create' or view.action == 'list':
                return False

        # All users are allowed to change their own password
        if view.action == 'password' or view.action == 'token' or view.action == 'current_user':
            return True

        return request.user.is_staff or request.user.is_superuser

    def has_object_permission(self, request, view, obj):
        '''
        This method is called only if has_permission has returned True.
        This is a second validation.
        '''
        return obj.user.pk == request.user.pk or request.user.is_superuser


class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True

        if 'share' in request.data and request.data['share']:
            if request.user.is_active and not request.user.is_staff and not request.user.is_superuser:
                return False

        return True

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            if request.user.is_staff or request.user.is_superuser:
                return True
            elif request.user.is_active:
                if request.user == obj.user or obj.id < 0 or obj.user is None:  # obj.id < 0 means static filter sets
                    return True
            return False

        return obj.user == request.user or request.user.is_superuser or request.user.is_staff
