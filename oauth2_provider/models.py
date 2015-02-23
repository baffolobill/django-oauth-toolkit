from __future__ import unicode_literals

from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse
from django.utils import timezone
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _

from mongoengine import (ReferenceField, StringField, BooleanField,
    Document, DateTimeField)
from mongodbforms.util import import_by_path

from .settings import oauth2_settings
from .compat import AUTH_USER_MODEL, parse_qsl, urlparse
from .generators import generate_client_secret, generate_client_id
from .validators import validate_uris


@python_2_unicode_compatible
class Application(Document):
    """
    An Application instance represents a Client on the Authorization server.
    Usually an Application is created manually by client's developers after
    logging in on an Authorization Server.

    Fields:

    * :attr:`client_id` The client identifier issued to the client during the
                        registration process as described in :rfc:`2.2`
    * :attr:`user` ref to a Django user
    * :attr:`redirect_uris` The list of allowed redirect uri. The string
                            consists of valid URLs separated by space
    * :attr:`client_type` Client type as described in :rfc:`2.1`
    * :attr:`authorization_grant_type` Authorization flows available to the
                                       Application
    * :attr:`client_secret` Confidential secret issued to the client during
                            the registration process as described in :rfc:`2.2`
    * :attr:`name` Friendly name for the Application
    """
    CLIENT_CONFIDENTIAL = 'confidential'
    CLIENT_PUBLIC = 'public'
    CLIENT_TYPES = (
        (CLIENT_CONFIDENTIAL, _('Confidential')),
        (CLIENT_PUBLIC, _('Public')),
    )

    GRANT_AUTHORIZATION_CODE = 'authorization-code'
    GRANT_IMPLICIT = 'implicit'
    GRANT_PASSWORD = 'password'
    GRANT_CLIENT_CREDENTIALS = 'client-credentials'
    GRANT_TYPES = (
        (GRANT_AUTHORIZATION_CODE, _('Authorization code')),
        (GRANT_IMPLICIT, _('Implicit')),
        (GRANT_PASSWORD, _('Resource owner password-based')),
        (GRANT_CLIENT_CREDENTIALS, _('Client credentials')),
    )

    client_id = StringField(max_length=100, unique=True, default=generate_client_id)
    user = ReferenceField(AUTH_USER_MODEL)
    redirect_uris = StringField(help_text=_("Allowed URIs list, space separated"))
    client_type = StringField(max_length=32, choices=CLIENT_TYPES)
    authorization_grant_type = StringField(max_length=32, choices=GRANT_TYPES)
    client_secret = StringField(max_length=255, null=True,
                                default=generate_client_secret)
    name = StringField(max_length=255, null=True)
    skip_authorization = BooleanField(default=False)

    meta = {
        'indexes': [
            'client_id',
            'client_secret',
        ]
    }

    @property
    def default_redirect_uri(self):
        """
        Returns the default redirect_uri extracting the first item from
        the :attr:`redirect_uris` string
        """
        if self.redirect_uris:
            return self.redirect_uris.split().pop(0)

        assert False, "If you are using implicit, authorization_code" \
                      "or all-in-one grant_type, you must define " \
                      "redirect_uris field in your Application model"

    def redirect_uri_allowed(self, uri):
        """
        Checks if given url is one of the items in :attr:`redirect_uris` string

        :param uri: Url to check
        """
        for allowed_uri in self.redirect_uris.split():
            parsed_allowed_uri = urlparse(allowed_uri)
            parsed_uri = urlparse(uri)

            if (parsed_allowed_uri.scheme == parsed_uri.scheme and
                parsed_allowed_uri.netloc == parsed_uri.netloc and
                parsed_allowed_uri.path == parsed_uri.path):

                aqs_set = set(parse_qsl(parsed_allowed_uri.query))
                uqs_set = set(parse_qsl(parsed_uri.query))

                if aqs_set.issubset(uqs_set):
                    return True

        return False

    def clean(self):
        from django.core.exceptions import ValidationError
        if not self.redirect_uris \
            and self.authorization_grant_type \
            in (Application.GRANT_AUTHORIZATION_CODE,
                Application.GRANT_IMPLICIT):
            error = _('Redirect_uris could not be empty with {0} grant_type')
            raise ValidationError(error.format(self.authorization_grant_type))

        # mongoengine doesn't support per field validation
        # so that do it here
        validate_uris(self.redirect_uris)

    def get_absolute_url(self):
        return reverse('oauth2_provider:detail', args=[str(self.id)])

    def __str__(self):
        return self.name or self.client_id



@python_2_unicode_compatible
class Grant(Document):
    """
    A Grant instance represents a token with a short lifetime that can
    be swapped for an access token, as described in :rfc:`4.1.2`

    Fields:

    * :attr:`user` The Django user who requested the grant
    * :attr:`code` The authorization code generated by the authorization server
    * :attr:`application` Application instance this grant was asked for
    * :attr:`expires` Expire time in seconds, defaults to
                      :data:`settings.AUTHORIZATION_CODE_EXPIRE_SECONDS`
    * :attr:`redirect_uri` Self explained
    * :attr:`scope` Required scopes, optional
    """
    user = ReferenceField(AUTH_USER_MODEL)
    code = StringField(max_length=255)  # code comes from oauthlib
    application = ReferenceField(oauth2_settings.APPLICATION_MODEL)
    expires = DateTimeField()
    redirect_uri = StringField(max_length=255)
    scope = StringField()

    meta = {
        'indexes': [
            'code',
        ]
    }

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        return timezone.now() >= self.expires

    def redirect_uri_allowed(self, uri):
        return uri == self.redirect_uri

    def __str__(self):
        return self.code


@python_2_unicode_compatible
class AccessToken(Document):
    """
    An AccessToken instance represents the actual access token to
    access user's resources, as in :rfc:`5`.

    Fields:

    * :attr:`user` The Django user representing resources' owner
    * :attr:`token` Access token
    * :attr:`application` Application instance
    * :attr:`expires` Expire time in seconds, defaults to
                      :data:`settings.ACCESS_TOKEN_EXPIRE_SECONDS`
    * :attr:`scope` Allowed scopes
    * :attr:`refresh_token` A refresh_token represents a token that can be swapped for a new
    access token when it expires.
    """
    user = ReferenceField(AUTH_USER_MODEL)
    token = StringField(max_length=255)
    application = ReferenceField(oauth2_settings.APPLICATION_MODEL)
    expires = DateTimeField()
    scope = StringField()
    refresh_token = StringField(max_length=255)

    meta = {
        'indexes': [
            'token',
            'refresh_token',
        ]
    }

    def is_valid(self, scopes=None):
        """
        Checks if the access token is valid.

        :param scopes: An iterable containing the scopes to check or None
        """
        return not self.is_expired() and self.allow_scopes(scopes)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        return timezone.now() >= self.expires

    def allow_scopes(self, scopes):
        """
        Check if the token allows the provided scopes

        :param scopes: An iterable containing the scopes to check
        """
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)

    def __str__(self):
        return self.token


def get_application_model():
    """ Return the Application model that is active in this project. """
    app_model = import_by_path(oauth2_settings.APPLICATION_MODEL)
    if app_model is None:
        e = "APPLICATION_MODEL refers to model {0} that has not been installed"
        raise ImproperlyConfigured(e.format(oauth2_settings.APPLICATION_MODEL))
    return app_model
