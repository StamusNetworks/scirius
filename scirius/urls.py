from django.conf.urls import patterns, include, url
from django.conf import settings

from django.contrib import admin

from views import homepage, KibanaProxyView, ElasticsearchProxyView

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^rules/', include('rules.urls')),
    url(r'^accounts/', include('accounts.urls')),
    url(r'^'+ settings.RULESET_MIDDLEWARE + '/', include('' + settings.RULESET_MIDDLEWARE + '.urls')),
    url('^$', homepage),
    # Forward "app/kibana.*" to kibana (work around to https://github.com/elastic/kibana/issues/5230)
    url(r'^(?P<path>app/kibana.*)$', KibanaProxyView.as_view()),
    # Forward timelion plugin
    url(r'^(?P<path>timelion/.*)$', KibanaProxyView.as_view()),
    url(r'^kibana/(?P<path>.*)$', KibanaProxyView.as_view()),
    url(r'^elasticsearch/(?P<path>.*)$', ElasticsearchProxyView.as_view()),
)
