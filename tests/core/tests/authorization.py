from django.test import TestCase
from django.http import HttpRequest
from django.contrib.auth.models import User, Permission
from core.models import Note
from tastypie.authorization import Authorization, ReadOnlyAuthorization, DjangoAuthorization
from tastypie import fields
from tastypie.resources import Resource, ModelResource

class NoAuthorization(Authorization):
    def to_read(self, bundle):
        return False
    def to_add(self, bundle):
        return False
    def to_change(self, bundle):
        return False
    def to_delete(self, bundle):
        return False

class NoAuthorizationNoteResource(ModelResource):
    class Meta:
        resource_name = 'notes'
        queryset = Note.objects.filter()
        authorization = Authorization()

class NoRulesNoteResource(ModelResource):
    class Meta:
        resource_name = 'notes'
        queryset = Note.objects.filter(is_active=True)
        authorization = Authorization()


class ReadOnlyNoteResource(ModelResource):
    class Meta:
        resource_name = 'notes'
        queryset = Note.objects.filter(is_active=True)
        authorization = ReadOnlyAuthorization()


class DjangoNoteResource(ModelResource):
    class Meta:
        resource_name = 'notes'
        queryset = Note.objects.filter(is_active=True)
        authorization = DjangoAuthorization()


class NotAModel(object):
    name = 'Foo'


class NotAModelResource(Resource):
    name = fields.CharField(attribute='name')

    class Meta:
        resource_name = 'notamodel'
        object_class = NotAModel
        authorization = DjangoAuthorization()


authorization_method_map = {
    'GET': 'to_read',
    'POST': 'to_add',
    'PUT': 'to_change',
    'PATCH': 'to_change',
    'DELETE': 'to_delete',
}

class AuthorizationTestCase(TestCase):
    fixtures = ['note_testdata']
    def setUp(self):
        self.basic_model = NoRulesNoteResource()

    def test_no_rules(self):
        request = HttpRequest()
        note_resource = NoRulesNoteResource()
        for method in ('GET', 'POST', 'PUT', 'DELETE'):
            request.method = method
            bundle = note_resource.build_bundle(request=request)
            self.assertTrue(getattr(note_resource._meta.authorization, authorization_method_map[method])(bundle))

    def test_read_only(self):
        request = HttpRequest()
        request.method = 'GET'
        read_only_resource = ReadOnlyNoteResource()

        bundle = read_only_resource.build_bundle(request=request)

        self.assertTrue(getattr(read_only_resource._meta.authorization, authorization_method_map['GET'])(bundle))

        for method in ('POST', 'PUT', 'DELETE'):
            request = HttpRequest()
            request.method = method
            bundle = read_only_resource.build_bundle(request=request)
            self.assertFalse(getattr(read_only_resource._meta.authorization, authorization_method_map[method])(bundle))

class DjangoAuthorizationTestCase(TestCase):
    fixtures = ['note_testdata']

    def setUp(self):
        self.add = Permission.objects.get_by_natural_key('add_note', 'core', 'note')
        self.change = Permission.objects.get_by_natural_key('change_note', 'core', 'note')
        self.delete = Permission.objects.get_by_natural_key('delete_note', 'core', 'note')
        self.user = User.objects.all()[0]
        self.user.user_permissions.clear()
        self.django_note_resource = DjangoNoteResource()

    def test_no_perms(self):
        # sanity check: user has no permissions
        self.assertFalse(self.user.get_all_permissions())

        request = HttpRequest()
        request.method = 'GET'
        request.user = self.user

        bundle = self.django_note_resource.build_bundle(request=request)
        # with no permissions, api is read-only
        self.assertTrue(getattr(self.django_note_resource._meta.authorization, \
            authorization_method_map['GET'])(bundle))

        for method in ('POST', 'PUT', 'DELETE'):
            request.method = method
            bundle = self.django_note_resource.build_bundle(request=request)
            self.assertFalse(getattr(self.django_note_resource._meta.authorization, \
                authorization_method_map[method])(bundle))

    def test_add_perm(self):
        request = HttpRequest()
        request.user = self.user

        # give add permission
        request.user.user_permissions.add(self.add)
        request.method = 'POST'
        bundle = self.django_note_resource.build_bundle(request=request)
        self.assertTrue(getattr(self.django_note_resource._meta.authorization, \
            authorization_method_map['POST'])(bundle))

    def test_change_perm(self):
        request = HttpRequest()
        request.user = self.user

        # give change permission
        request.user.user_permissions.add(self.change)
        request.method = 'PUT'
        bundle = self.django_note_resource.build_bundle(request=request)
        self.assertTrue(getattr(self.django_note_resource._meta.authorization, \
            authorization_method_map['PUT'])(bundle))

    def test_delete_perm(self):
        request = HttpRequest()
        request.user = self.user

        # give delete permission
        request.user.user_permissions.add(self.delete)
        request.method = 'DELETE'
        bundle = self.django_note_resource.build_bundle(request=request)
        self.assertTrue(getattr(self.django_note_resource._meta.authorization, \
            authorization_method_map['DELETE'])(bundle))


    def test_all(self):
        request = HttpRequest()
        request.user = self.user

        request.user.user_permissions.add(self.add)
        request.user.user_permissions.add(self.change)
        request.user.user_permissions.add(self.delete)

        for method in ('GET', 'OPTIONS', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH'):
            request.method = method
            self.assertTrue(DjangoNoteResource()._meta.authorization.is_authorized(request))

    def test_not_a_model(self):
        request = HttpRequest()
        request.user = self.user

        # give add permission
        request.user.user_permissions.add(self.add)
        request.method = 'POST'
        bundle = self.django_note_resource.build_bundle(request=request)
        self.assertTrue(getattr(self.django_note_resource._meta.authorization, \
            authorization_method_map['POST'])(bundle))

    def test_patch_perms(self):
        request = HttpRequest()
        request.user = self.user
        request.method = 'PATCH'
        bundle = self.django_note_resource.build_bundle(request=request)

        # Not enough.
        request.user.user_permissions.add(self.add)
        self.assertFalse(getattr(self.django_note_resource._meta.authorization, \
            authorization_method_map['PATCH'])(bundle))

        # Still not enough.
        request.user.user_permissions.add(self.change)
        self.assertFalse(getattr(self.django_note_resource._meta.authorization, \
            authorization_method_map['PATCH'])(bundle))

        # Much better.
        request.user.user_permissions.add(self.delete)
        # Nuke the perm cache. :/
        del request.user._perm_cache
        self.assertTrue(getattr(self.django_note_resource._meta.authorization, \
            authorization_method_map['PATCH'])(bundle))

    def test_unrecognized_method(self):
        request = HttpRequest()
        request.user = self.user

        # Check a non-existent HTTP method.
        request.method = 'EXPLODE'
        self.assertFalse(DjangoNoteResource()._meta.authorization.is_authorized(request))


