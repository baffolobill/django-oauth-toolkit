from django import forms

from mongodbforms import DocumentForm, MongoCharField
from .models import get_application_model


class AllowForm(forms.Form):
    allow = forms.BooleanField(required=False)
    redirect_uri = MongoCharField(widget=forms.HiddenInput())
    scope = MongoCharField(required=False, widget=forms.HiddenInput())
    client_id = MongoCharField(widget=forms.HiddenInput())
    state = MongoCharField(required=False, widget=forms.HiddenInput())
    response_type = MongoCharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        data = kwargs.get('data')
        # backwards compatible support for plural `scopes` query parameter
        if data and 'scopes' in data:
            data['scope'] = data['scopes']
        return super(AllowForm, self).__init__(*args, **kwargs)


class RegistrationForm(DocumentForm):
    """
    TODO: add docstring
    """
    class Meta:
        document = get_application_model()
        fields = ('name', 'client_id', 'client_secret', 'client_type', 'authorization_grant_type', 'redirect_uris')
