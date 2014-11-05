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
    url(r'^kibana/(?P<path>.*)$', KibanaProxyView.as_view()),
    url(r'^elasticsearch/(?P<path>.*)$', ElasticsearchProxyView.as_view()),
)
