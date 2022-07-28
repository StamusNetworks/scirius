
from django.urls import re_path, include
from django.conf import settings

from .views import homepage, KibanaProxyView, EveboxProxyView, MolochProxyView, static_redirect, ui_view
from .rest_api import router

urlpatterns = [
    re_path(r'^rules/', include('rules.urls')),
    re_path(r'^accounts/', include('accounts.urls')),
    re_path(r'^viz/', include('viz.urls')),
    re_path(r'^' + settings.RULESET_MIDDLEWARE + '/', include('' + settings.RULESET_MIDDLEWARE + '.urls')),
    re_path(r'^rest/', include(router.urls)),
    re_path(r'^stamus(/.*)?$', ui_view),
    re_path('^$', homepage),
    # Forward "app/kibana.*" to kibana (work around to https://github.com/elastic/kibana/issues/5230)
    re_path(r'^(?P<path>app/.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>status.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>api.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>plugins.*)$', KibanaProxyView.as_view()),
    # Forward timelion plugin
    re_path(r'^(?P<path>timelion/.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>bundles/.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>elasticsearch/.*)$', KibanaProxyView.as_view()),
    re_path(r'^kibana/(?P<path>.*)$', KibanaProxyView.as_view()),
    re_path(r'^evebox/(?P<path>.*)$', EveboxProxyView.as_view()),
    # Kibana 5.2 specific
    re_path(r'^(?P<path>ui/fonts.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>es_admin.*)$', KibanaProxyView.as_view()),
    # Kibana 7 specific
    re_path(r'^(?P<path>ui/.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>dlls/.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>translations/.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>internal/.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>goto/.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>[\d]{5}/.*)$', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>bootstrap(-anonymous)?\.js$)', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>spaces/.*$)', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>node_modules/.*$)', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>login/?.*$)', KibanaProxyView.as_view()),
    re_path(r'^(?P<path>logout/?.*$)', KibanaProxyView.as_view()),

    # Moloch proxy
    re_path(r'^moloch/(?P<path>.*)$', MolochProxyView.as_view()),
]

if settings.STATIC_AUTHENTICATED:
    urlpatterns += [
        re_path(r'^static/(?P<static_path>.*)$', static_redirect, name='static_redirect'),
    ]
