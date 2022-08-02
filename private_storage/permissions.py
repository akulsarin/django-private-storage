"""
Possible functions for the ``PRIVATE_STORAGE_AUTH_FUNCTION`` setting.
"""
import django
from knox.auth import TokenAuthentication

if django.VERSION >= (1, 10):
    def allow_authenticated(private_file):
        try:
            authenticated = TokenAuthentication().authenticate(private_file.request)
        except:
            return False
        if not authenticated:
            return False
        user, _ = authenticated
        is_authenticated = (str(user.id) == private_file.relative_name.split('/')[1])
        return is_authenticated

    def allow_staff(private_file):
        request = private_file.request
        return request.user.is_authenticated and request.user.is_staff

    def allow_superuser(private_file):
        request = private_file.request
        return request.user.is_authenticated and request.user.is_superuser
else:
    def allow_authenticated(private_file):
        return private_file.request.user.is_authenticated()

    def allow_staff(private_file):
        request = private_file.request
        return request.user.is_authenticated() and request.user.is_staff

    def allow_superuser(private_file):
        request = private_file.request
        return request.user.is_authenticated() and request.user.is_superuser
