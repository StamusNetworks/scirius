from django.conf.urls import patterns, include, url
from django.conf import settings

from django.contrib import admin

from views import homepage, scirius_login, scirius_logout, KibanaProxyView, ElasticsearchProxyView

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^rules/', include('rules.urls')),
    url(r'^'+ settings.RULESET_MIDDLEWARE + '/', include('' + settings.RULESET_MIDDLEWARE + '.urls')),
    url('^$', homepage),
    url('^login/$', scirius_login),
    url('^logout/$', scirius_logout),
    url(r'^kibana/(?P<path>.*)$', KibanaProxyView.as_view()),
    url(r'^elasticsearch/(?P<path>.*)$', ElasticsearchProxyView.as_view()),
)
