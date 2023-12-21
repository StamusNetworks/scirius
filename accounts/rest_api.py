
from django.core import exceptions
from django.contrib.auth.models import User
from django.contrib.auth import password_validation, logout
from django.conf import settings
from django.utils import timezone

from rest_framework import serializers, viewsets
from rest_framework.routers import DefaultRouter
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.validators import UniqueValidator
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied

from accounts.models import SciriusUser
from rules.rest_api import CommentSerializer
from rules.models import UserAction, get_system_settings
from rules.rest_permissions import has_group_permission
from scirius.utils import get_middleware_module

import pytz
from datetime import timedelta

TIMEZONES = [(x, x) for x in pytz.all_timezones]


class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=False, validators=[UniqueValidator(queryset=User.objects.all())])
    password = serializers.CharField(required=False)

    class Meta:
        model = User
        extra_kwargs = {
            'password': {'write_only': True},
            'date_joined': {'read_only': True}
        }
        read_only_fields = ('auth_token', 'date_joined',)
        fields = ('username', 'password', 'first_name', 'last_name', 'is_active', 'email', 'date_joined')


class UserLightSerializer(serializers.ModelSerializer):
    role = serializers.CharField(required=False, source='groups')

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'role')
        extra_kwargs = {
            'role': {'read_only': True}
        }
        read_only_fields = ('role',)


class AccountLightSerializer(serializers.ModelSerializer):
    user = UserLightSerializer(required=True, partial=True)
    timezone = serializers.ChoiceField(required=True, choices=TIMEZONES)

    class Meta:
        model = SciriusUser
        fields = ('pk', 'user', 'timezone')

    def to_representation(self, instance):
        data = super().to_representation(instance)
        user = data.pop('user', None)

        if user is not None:
            data.update(user)

        role = instance.user.groups.first()
        data['role'] = role.name if role else ''

        return data

    def to_internal_value(self, data):
        for key, value in data.items():
            if key not in ('first_name', 'last_name', 'email', 'timezone'):
                raise serializers.ValidationError({key: 'is not a valid field'})

        data = data.copy()
        timezone = data.pop('timezone', None)
        user_serializer = UserLightSerializer(data=data)
        user_serializer.is_valid(raise_exception=True)
        res = {'user': user_serializer.validated_data}
        if timezone:
            res['timezone'] = timezone
        return res

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user')
        user = instance.user

        for key, value in user_data.items():
            if hasattr(user, key):
                setattr(user, key, value)

        timezone = validated_data.get('timezone', instance.timezone)
        if timezone not in pytz.all_timezones:
            # to avoid deadlock
            if instance.timezone not in pytz.all_timezones:
                instance.timezone = 'UTC'
                instance.save()
            raise serializers.ValidationError({'timezone': ['Not a valid choice.']})

        instance.timezone = timezone
        instance.save()
        user.save()
        return instance


class AccountSerializer(serializers.ModelSerializer):
    user = UserSerializer(required=True, partial=True)
    timezone = serializers.ChoiceField(required=True, choices=TIMEZONES)
    role = serializers.CharField(required=True, source='user.groups')
    no_tenant = serializers.BooleanField(required=False)
    all_tenants = serializers.BooleanField(required=False)
    tenants = serializers.PrimaryKeyRelatedField(
        source='sciriususerapp.tenants',
        queryset=get_middleware_module('common').get_tenants(),
        many=True
    )

    class Meta:
        model = SciriusUser
        fields = ('pk', 'user', 'timezone', 'role', 'no_tenant', 'all_tenants', 'tenants')

    def to_representation(self, instance):
        data = super().to_representation(instance)
        user = data.pop('user', None)

        if user is not None:
            user.pop('password', None)
            data.update(user)

        role = instance.user.groups.first()
        data['role'] = role.name if role else ''
        if get_middleware_module('common').has_multitenant():
            data['tenants'] = instance.get_tenants().values_list('pk', flat=True)
            data['no_tenant'] = instance.has_no_tenant()
            data['all_tenants'] = instance.has_all_tenants()

        return data

    def to_internal_value(self, data):
        data = data.copy()
        timezone = data.pop('timezone', None)
        role = data.pop('role', None)
        user_serializer = UserSerializer(data=data)
        user_serializer.is_valid(raise_exception=True)

        res = {'user': user_serializer.validated_data}

        if timezone is not None:
            res['timezone'] = timezone

        if role is not None:
            res['user']['role'] = [role]

        if 'tenants' in data:
            if not isinstance(data['tenants'], (list, tuple)):
                raise serializers.ValidationError({'tenants': ['Wrong format: it should be "[1, 4]"']})

            all_tenants = get_middleware_module('common').get_tenants().values_list('pk', flat=True)
            for tenant in data['tenants']:
                if tenant not in all_tenants:
                    raise serializers.ValidationError({'tenants': ['pk "{}" does not exist'.format(tenant)]})

        for item in ('no_tenant', 'all_tenants'):
            if item in data:
                if not isinstance(data[item], bool):
                    raise serializers.ValidationError({item: ['boolean value requested']})

        if self.instance:
            res.update({
                'sciriususerapp': {
                    'tenants': data.get('tenants', self.instance.get_tenants().values_list('pk', flat=True)),
                    'no_tenant': data.get('no_tenant', self.instance.has_no_tenant()),
                    'all_tenants': data.get('all_tenants', self.instance.has_all_tenants())
                }
            })
        else:
            res.update({
                'sciriususerapp': {
                    'tenants': data.get('tenants', []),
                    'no_tenant': data.get('no_tenant', False),
                    'all_tenants': data.get('all_tenants', False)
                }
            })

        return res

    def create(self, validated_data):
        user_data = validated_data.pop('user')

        errors = {}
        if 'username' not in user_data:
            errors['username'] = ['This field is required.']

        if 'password' not in user_data:
            errors['password'] = ['This field is required.']

        if len(errors) > 0:
            raise serializers.ValidationError(errors)

        if 'timezone' not in validated_data:
            validated_data['timezone'] = 'UTC'

        if validated_data['timezone'] not in pytz.all_timezones:
            raise serializers.ValidationError({'timezone': ['Not a valid choice.']})

        password = user_data.pop('password')
        role = user_data.pop('role', None)
        try:
            password_validation.validate_password(password=password, user=User)
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({'password': [e.message]})

        user = User.objects.create(**user_data)
        user.set_password(password)
        user.save()

        if role:
            user.groups.set(role)

        sciriususerapp_data = validated_data.pop('sciriususerapp', {})
        sciriususer = SciriusUser.objects.create(user=user, **validated_data)
        get_middleware_module('common').update_scirius_user_class(user, sciriususerapp_data)
        return sciriususer

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user')
        user = instance.user

        for key, value in user_data.items():
            if key == 'password':
                raise PermissionDenied({'password': 'You do not have permission to perform this action'})

            if hasattr(user, key) or key == 'role':
                if key != 'role':
                    setattr(user, key, value)
                else:
                    user.groups.set(value)

        timezone = validated_data.get('timezone', instance.timezone)
        if timezone not in pytz.all_timezones:
            # to avoid deadlock
            if instance.timezone not in pytz.all_timezones:
                instance.timezone = 'UTC'
                instance.save()
            raise serializers.ValidationError({'timezone': ['Not a valid choice.']})

        instance.timezone = timezone
        instance.save()
        user.save()
        get_middleware_module('common').update_scirius_user_class(user, validated_data.get('sciriususerapp', {}))
        return instance


class ChangePasswordSuperUserSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True)
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), required=True)

    def validate_new_password(self, password):
        try:
            password_validation.validate_password(password=password, user=User)
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({'password': [str(e)]})
        return password


class ChangePasswordSerializer(ChangePasswordSuperUserSerializer):
    old_password = serializers.CharField(required=True)


class AccountViewSet(viewsets.ModelViewSet):
    """
    =============================================================================================================================================================
    ==== GET ====\n
    Show all Scirius Users:\n
        curl -k https://x.x.x.x/rest/accounts/sciriususer/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK

    ==== POST ====\n
    Create Scirius User with super user:\n
        curl -k https://x.x.x.x/rest/accounts/sciriususer/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"username": "sonic", "password": "69scirius69", "timezone": "UTC", "role": 1}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":4,"timezone":"UTC","username":"sonic","first_name":"","last_name":"","is_staff":false,"is_active":true,"email":"","date_joined":"2018-05-24T16:44:06.811367+02:00", "role": "Superuser"}

    Create/Get Token for a Scirius User :\n
        curl -v -k https://192.168.0.40/rest/accounts/sciriususer/<pk-sciriususer>/token/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X GET

    Return:\n
        HTTP/1.1 200 OK
        {"token":"64f803c77076b50081543d01ed9d1c4f52aec104"}

    /|\\ Active/staff users can only update their own password.
    Modify Scirius User own password (active/staff):\n
        curl -k https://x.x.x.x/rest/accounts/sciriususer/<pk-sciriususer>/password/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"old_password": "69scirius69", "new_password": "51scirius51"}'

    Super user modify any Scirius User password (without old_password):\n
        curl -k https://x.x.x.x/rest/accounts/sciriususer/<pk-sciriususer>/password/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"new_password": "51scirius51"}'

    Return:\n
        HTTP/1.1 200 OK
        {"password":"updated"}

    ==== PATCH/PUT ====\n
    Update Scirius user tenants:\n
        curl -k https://x.x.x.x/rest/accounts/sciriususer/<pk-sciriususer>/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X PATCH -d '{"tenants": [1,3,5,6], "role": 1}'

    =============================================================================================================================================================
    """

    queryset = SciriusUser.objects.select_related('user').order_by('-user__date_joined')
    REQUIRED_GROUPS = {
        'READ': ('rules.configuration_auth',),
        'WRITE': ('rules.configuration_auth',),
    }

    def get_permissions(self):
        if self.action in ('current_user', 'session_activity'):
            return [IsAuthenticated()]
        return super().get_permissions()

    def get_serializer_class(self):
        if self.request.method in ('PUT', 'PATCH'):
            if not self.request.user.has_perm('rules.configuration_auth'):
                return AccountLightSerializer

        return AccountSerializer

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        comment = data.pop('comment', None)

        serializer = AccountSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)
        UserAction.create(
            action_type='create_user',
            comment=comment_serializer.validated_data['comment'],
            request=request,
            new_user=serializer.instance.user
        )
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, headers=headers, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        old_user = self.get_object()
        # Do not need to copy 'request.data' and pop 'comment'
        # because we are not using serializer there
        comment = request.data.get('comment', None)
        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)

        UserAction.create(
            action_type='delete_user',
            request=request,
            old_user=old_user.user,
            comment=comment_serializer.validated_data['comment']
        )
        return super(AccountViewSet, self).destroy(request, *args, **kwargs)

    @has_group_permission(['rules.configuration_auth'], owner_allowed=True)
    def update(self, request, pk, *args, **kwargs):
        data = request.data.copy()
        comment = data.pop('comment', None)

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=False)
        serializer.is_valid(raise_exception=True)

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)
        UserAction.create(
            action_type='edit_user',
            comment=comment_serializer.validated_data['comment'],
            request=request,
            other_user=serializer.instance.user
        )
        return super(AccountViewSet, self).update(request, pk, *args, **kwargs)

    @has_group_permission(['rules.configuration_auth'], owner_allowed=True)
    def partial_update(self, request, pk, *args, **kwargs):
        data = request.data.copy()
        comment = data.pop('comment', None)

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)
        UserAction.create(
            action_type='edit_user',
            comment=comment_serializer.validated_data['comment'],
            request=request,
            other_user=serializer.instance.user
        )
        return super(AccountViewSet, self).update(request, pk, partial=True, *args, **kwargs)

    @action(detail=True, methods=['get', 'post'])
    @has_group_permission(['rules.configuration_auth'], owner_allowed=True)
    def token(self, request, *args, **kwargs):
        scirius_user = self.get_object()
        tokens = Token.objects.filter(user=scirius_user.user)
        token = ''

        if request.method == 'GET':
            if tokens.count() > 0:
                token = tokens[0].key
        else:
            if tokens.count() > 0:
                tokens[0].delete()

            token = Token.objects.create(user=scirius_user.user).key

            data = request.data.copy()
            comment = data.pop('comment', None)

            comment_serializer = CommentSerializer(data={'comment': comment})
            comment_serializer.is_valid(raise_exception=True)
            UserAction.create(
                action_type='edit_user_token',
                comment=comment_serializer.validated_data['comment'],
                request=request,
                other_user=scirius_user.user
            )

        return Response({'token': token})

    @action(detail=True, methods=['post'])
    @has_group_permission(['rules.configuration_auth'], owner_allowed=True)
    def password(self, request, pk, *args, **kwargs):
        data = request.data.copy()
        scirius_user = self.get_object()

        data['user'] = scirius_user.user.pk
        if request.user.has_perm('rules.configuration_auth'):
            pass_serializer = ChangePasswordSuperUserSerializer(data=data)
            pass_serializer.is_valid(raise_exception=True)

        else:
            pass_serializer = ChangePasswordSerializer(data=data)
            pass_serializer.is_valid(raise_exception=True)

            if 'old_password' not in pass_serializer.validated_data:
                raise serializers.ValidationError({'old_password': ['Old password is needed']})

            if not scirius_user.user.check_password(pass_serializer.validated_data.get('old_password')):
                raise serializers.ValidationError({'old_password': ['Wrong password']})

        scirius_user.user.set_password(pass_serializer.validated_data.get('new_password'))
        scirius_user.user.save()
        scirius_user.save()

        comment = data.pop('comment', None)
        comment_serializer = CommentSerializer(data={'comment': comment})
        comment_serializer.is_valid(raise_exception=True)
        UserAction.create(
            action_type='edit_user_password',
            comment=comment_serializer.validated_data['comment'],
            request=request,
            other_user=scirius_user.user
        )
        return Response({'password': 'updated'})

    @action(detail=False, methods=['get'])
    def current_user(self, request, *args, **kwargs):
        user = request.user
        if user.__class__.__name__ == 'FakeUser' and settings.DEBUG:
            return Response(SciriusUser.FAKE_USER)
        sciriususer = SciriusUser.objects.get(user=user)
        return Response(sciriususer.to_dict())

    @action(detail=False, methods=['post'])
    def session_activity(self, request, *args, **kwargs):
        timeout = int(request.data.get('timeout', '0'))
        cookie_age = get_system_settings().custom_cookie_age
        session_cookie_age = get_system_settings().session_cookie_age

        disconnect = timeout >= cookie_age * 3600
        if session_cookie_age > 0 and 'session_start' in request.session:
            disconnect |= request.session['session_start'] + timedelta(hours=session_cookie_age) < timezone.now()

        if disconnect:
            logout(request)
        else:
            expiry = cookie_age * 3600 - timeout
            request.session.set_expiry(expiry)
        return Response({'disconnect': disconnect})


router = DefaultRouter()
router.register('accounts/sciriususer', AccountViewSet, basename='sciriususer')
