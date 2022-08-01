"""
Possible functions for the ``PRIVATE_STORAGE_AUTH_FUNCTION`` setting.
"""
import django
from knox.models import AuthToken
from knox import crypto

def extract_user(headers):
    auth_list = None
    user = None
    try:
        auth_list = headers['Authorization'].split(' ')
    except KeyError:
        return user
    if auth_list[0] != 'Token' or len(auth_list) != 2:
        return user
    token = auth_list[1]
    digest = crypto.hash_token(token)
    user = AuthToken.objects.get(digest=digest).user
    return user

if django.VERSION >= (1, 10):
    def allow_authenticated(private_file):
        user = extract_user(private_file.request.headers)
        if not user:
            return False
        is_authenticated = (user.picture == private_file.relative_name)
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
