
from django.core import exceptions
from django.contrib.auth.models import User
from django.contrib.auth import password_validation

from rest_framework import serializers, viewsets
from rest_framework.routers import DefaultRouter
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.decorators import detail_route, list_route
from rest_framework.exceptions import PermissionDenied
from rest_framework.validators import UniqueValidator
from rest_framework import status

from accounts.models import SciriusUser
from rules.rest_permissions import IsCurrentUserOrSuperUserOrReadOnly
from rules.rest_api import CommentSerializer
from rules.models import UserAction

import pytz

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
        fields = ('username', 'password', 'first_name', 'last_name', 'is_staff', 'is_active', 'is_superuser', 'email', 'date_joined')


class AccountSerializer(serializers.ModelSerializer):
    user = UserSerializer(required=True, partial=True)
    timezone = serializers.ChoiceField(required=True, choices=TIMEZONES)

    class Meta:
        model = SciriusUser
        fields = ('pk', 'user', 'timezone')

    def to_representation(self, instance):
        data = super(AccountSerializer, self).to_representation(instance)
        user = data.pop('user', None)

        if user is not None:
            user.pop('password', None)
            data.update(user)

        return data

    def to_internal_value(self, data):
        data = data.copy()
        timezone = data.pop('timezone', None)
        user_serializer = UserSerializer(data=data)
        user_serializer.is_valid(raise_exception=True)

        res = {'user': user_serializer.validated_data}

        if timezone is not None:
            res['timezone'] = timezone

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
        try:
            password_validation.validate_password(password=password, user=User)
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({'password': [e.message]})

        user = User.objects.create(**user_data)
        user.set_password(password)
        user.save()

        return SciriusUser.objects.create(user=user, **validated_data)

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user')
        user = instance.user

        for key, value in user_data.items():
            if key == 'password':
                raise serializers.ValidationError({'password': 'You do not have permission to perform this action'})

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
        curl -k https://x.x.x.x/rest/accounts/sciriususer/ -H 'Authorization: Token <token>' -H 'Content-Type: application/json'  -X POST -d '{"username": "sonic", "password": "69scirius69", "timezone": "UTC"}'

    Return:\n
        HTTP/1.1 201 Created
        {"pk":4,"timezone":"UTC","username":"sonic","first_name":"","last_name":"","is_staff":false,"is_active":true,"is_superuser":false,"email":"","date_joined":"2018-05-24T16:44:06.811367+02:00"}

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

    =============================================================================================================================================================
    """

    queryset = SciriusUser.objects.select_related('user').order_by('-user__date_joined')
    serializer_class = AccountSerializer
    permission_classes = (IsCurrentUserOrSuperUserOrReadOnly, )

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
            user=request.user,
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
            user=request.user,
            old_user=old_user.user,
            comment=comment_serializer.validated_data['comment']
        )
        return super(AccountViewSet, self).destroy(request, *args, **kwargs)

    def update(self, request, pk, *args, **kwargs):
        if request.user.is_superuser is False:
            for right in ('is_active', 'is_staff', 'is_superuser',):
                if right in request.data:
                    raise PermissionDenied({right: 'You do not have permission to perform this action.'})

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
            user=request.user,
            other_user=serializer.instance.user
        )
        return super(AccountViewSet, self).update(request, pk, *args, **kwargs)

    def partial_update(self, request, pk, *args, **kwargs):
        if request.user.is_superuser is False:
            for right in ('is_active', 'is_staff', 'is_superuser',):
                if right in request.data:
                    raise PermissionDenied({right: 'You do not have permission to perform this action.'})

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
            user=request.user,
            other_user=serializer.instance.user
        )
        return super(AccountViewSet, self).update(request, pk, partial=True, *args, **kwargs)

    @detail_route(methods=['get', 'post'])
    def token(self, request, *args, **kwargs):
        scirius_user = self.get_object()
        tokens = Token.objects.filter(user=scirius_user.user)
        token = ''

        if request.method == 'GET':
            if len(tokens) > 0:
                token = tokens[0].key
        else:
            if len(tokens) > 0:
                tokens[0].delete()

            token = Token.objects.create(user=scirius_user.user).key

            data = request.data.copy()
            comment = data.pop('comment', None)

            comment_serializer = CommentSerializer(data={'comment': comment})
            comment_serializer.is_valid(raise_exception=True)
            UserAction.create(
                action_type='edit_user_token',
                comment=comment_serializer.validated_data['comment'],
                user=request.user,
                other_user=scirius_user.user
            )

        return Response({'token': token})

    @detail_route(methods=['post'])
    def password(self, request, pk, *args, **kwargs):
        data = request.data.copy()
        scirius_user = self.get_object()

        data['user'] = scirius_user.user.pk
        if request.user.is_superuser:
            pass_serializer = ChangePasswordSuperUserSerializer(data=data)
        else:
            pass_serializer = ChangePasswordSerializer(data=data)
        pass_serializer.is_valid(raise_exception=True)

        if request.user.is_superuser is False:
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
            user=request.user,
            other_user=scirius_user.user
        )
        return Response({'password': 'updated'})

    @list_route(methods=['get'])
    def current_user(self, request, *args, **kwargs):
        user = request.user
        sciriususer = SciriusUser.objects.get(user=user)
        return Response(sciriususer.to_dict())


router = DefaultRouter()
router.register('accounts/sciriususer', AccountViewSet)
