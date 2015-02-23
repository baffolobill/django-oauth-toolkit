from __future__ import absolute_import
from django.conf.urls import patterns, url, include

from . import views

urlpatterns = patterns(
    '',
    url(r'^authorize/$', views.AuthorizationView.as_view(), name="authorize"),
    url(r'^token/$', views.TokenView.as_view(), name="token"),
    url(r'^revoke_token/$', views.RevokeTokenView.as_view(), name="revoke-token"),
)

# Application management views
urlpatterns += patterns('',
    url(r'^applications/', include(patterns('',
        url(r'^$', views.ApplicationList.as_view(), name="list"),
        url(r'^register/$', views.ApplicationRegistration.as_view(), name="register"),
        url(r'^(?P<pk>[a-f0-9]+)/', include(patterns('',
            url(r'^$', views.ApplicationDetail.as_view(), name="detail"),
            url(r'^delete/$', views.ApplicationDelete.as_view(), name="delete"),
            url(r'^update/$', views.ApplicationUpdate.as_view(), name="update"),
        ))),
    ))),
)
