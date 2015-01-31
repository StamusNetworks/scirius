"""
Django settings for scirius project.

For more information on this file, see
https://docs.djangoproject.com/en/1.6/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.6/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
from distutils.version import LooseVersion
from django import get_version
import os
BASE_DIR = os.path.dirname(os.path.dirname(__file__))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.6/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'p8o5%vq))8h2li08c%k3id(wwo*u(^dbdmx2tv#t(tb2pr9@n-'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

TEMPLATE_DEBUG = True

ALLOWED_HOSTS = []

# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_tables2',
    'bootstrap3',
    'rules',
    'suricata',
    'accounts',
)

if LooseVersion(get_version()) < LooseVersion('1.7'):
    INSTALLED_APPS += ('south', )

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'scirius.loginrequired.LoginRequiredMiddleware',
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.core.context_processors.request',
    'django.contrib.auth.context_processors.auth'
)

ROOT_URLCONF = 'scirius.urls'

WSGI_APPLICATION = 'scirius.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.6/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

# Internationalization
# https://docs.djangoproject.com/en/1.6/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.6/howto/static-files/

STATIC_URL = '/static/'

# Elastic search

USE_ELASTICSEARCH = True
#ELASTICSEARCH_ADDRESS = "127.0.0.1:9200"
ELASTICSEARCH_ADDRESS = "localhost:9200"
# You can use a star to avoid timestamping expansion for example 'logstash-*'
ELASTICSEARCH_LOGSTASH_INDEX = "logstash-"
# use hourly, daily to indicate the logstash index building recurrence
ELASTICSEARCH_LOGSTASH_TIMESTAMPING = "daily"

# Kibana
USE_KIBANA = False
# Use django as a reverse proxy for kibana request
# This will allow you to use scirius authentication to control
# access to Kibana
KIBANA_PROXY = False
# Kibana URL
KIBANA_URL = "http://localhost:9292"
# Number of dashboards to display
KIBANA_DASHBOARDS_COUNT = 20

# Proxy parameters
# Set USE_PROXY to True to use a proxy to fetch ruleset update.
# PROXY_PARAMS contains the proxy parameters.
# If user is set in PROXY_PARAMS then basic authentication will
# be used.
USE_PROXY = False
PROXY_PARAMS = { 'http': "http://proxy:3128", 'https': "http://proxy:3128" }
# For basic authentication you can use
# PROXY_PARAMS = { 'http': "http://user:pass@proxy:3128", 'https': "http://user:pass@proxy:3128" }

GIT_SOURCES_BASE_DIRECTORY = os.path.join(BASE_DIR, 'git-sources/')

# Ruleset generator framework
RULESET_MIDDLEWARE = 'suricata'

LOGIN_URL = '/accounts/login/'

try:
    from local_settings import *
except:
    pass

if KIBANA_PROXY:
    INSTALLED_APPS += ( 'revproxy',)
