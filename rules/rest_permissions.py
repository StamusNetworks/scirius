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
        if view.action == 'password' or view.action == 'token':
            return True

        return request.user.is_staff or request.user.is_superuser

    def has_object_permission(self, request, view, obj):
        '''
        This method is called only if has_permission has returned True.
        This is a second validation.
        '''
        return obj.user.pk == request.user.pk or request.user.is_superuser
