from django.conf.urls import patterns, include, url
from django.conf import settings

from django.contrib import admin

from views import homepage, scirius_login

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^rules/', include('rules.urls')),
    url(r'^'+ settings.RULESET_MIDDLEWARE + '/', include('' + settings.RULESET_MIDDLEWARE + '.urls')),
    url('^$', homepage),
    url('^login/$', scirius_login),
)
