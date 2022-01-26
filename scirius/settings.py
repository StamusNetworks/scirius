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

SCIRIUS_FLAVOR = "Scirius CE"
SCIRIUS_VERSION = "3.8.0"
SCIRIUS_LONG_NAME = "Suricata Management"

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.6/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'p8o5%vq))8h2li08c%k3id(wwo*u(^dbdmx2tv#t(tb2pr9@n-'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = []

# Application definition

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_tables2',
    'bootstrap3',
    'dbbackup',
    'viz',
    'rules',
    'scirius',
    'suricata',
    'accounts',
    'rest_framework',
    'rest_framework.authtoken',
    'django_filters',
    'webpack_loader',
)

if LooseVersion(get_version()) < LooseVersion('1.7'):
    INSTALLED_APPS += ('south', )

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'scirius.loginrequired.LoginRequiredMiddleware',
    'scirius.utils.TimezoneMiddleware',
    'csp.middleware.CSPMiddleware',
    'django_cprofile_middleware.middleware.ProfilerMiddleware'
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WEBPACK_LOADER = {
    'DEFAULT': {
        'BUNDLE_DIR_NAME': 'rules/static/bundles/',
        'STATS_FILE': os.path.join(BASE_DIR, 'rules/static/webpack-stats-hunt.prod.json'),
        'LOADER_CLASS': 'rules.hunt_webpack.HuntLoader',
        'CACHE': False
    },
    'UI': {
        'BUNDLE_DIR_NAME': 'rules/static/bundles/',
        'STATS_FILE': os.path.join(BASE_DIR, 'rules/static/webpack-stats-ui.prod.json'),
    }
}

# For development (set that up in your local settings)
# WEBPACK_LOADER = {
#     'DEFAULT': {
#             'BUNDLE_DIR_NAME': 'bundles/',
#             'STATS_FILE': os.path.join(BASE_DIR, 'webpack-stats.dev.json'),
#         }
# }

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

# Password validation
# https://docs.djangoproject.com/en/1.11/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'my_cache_table',
    }
}


LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'fileformat': {
            'format': '%(asctime)s %(levelname)s %(message)s'
        },
        'raw': {
            'format': '%(asctime)s %(message)s'
        },
    },
    'handlers': {
        'elasticsearch': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/var/log/scirius/elasticsearch.log',
            'formatter': 'raw',
        },
    },
    'loggers': {
        'elasticsearch': {
            'handlers': ['elasticsearch'],
            'level': 'INFO',
            'propagate': True,
        },
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

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = True

CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'",)
CSP_INCLUDE_NONCE_IN = ['script-src']
CSP_EXCLUDE_URL_PREFIXES = ('/evebox',)

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
        'rules.rest_permissions.HasGroupPermission',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.OrderingFilter',
        'rest_framework.filters.SearchFilter',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 30
}

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.6/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATIC_AUTHENTICATED = False

# Suricata binary
SURICATA_BINARY = "suricata"

SURICATA_NAME_IS_HOSTNAME = False

# Do we have the doc
SCIRIUS_HAS_DOC = True

# Scirius run in SELKS
SCIRIUS_IN_SELKS = True

# Sources update
DEFAULT_SOURCE_INDEX_URL = "https://www.openinfosecfoundation.org/rules/index.yaml"

# Elastic search

USE_ELASTICSEARCH = True
# ELASTICSEARCH_ADDRESS = "127.0.0.1:9200"
ELASTICSEARCH_ADDRESS = "localhost:9200"
# You can use a star to avoid timestamping expansion for example 'logstash-*'
ELASTICSEARCH_LOGSTASH_INDEX = "logstash-"
# You can change following value if you have different indexes for stats and alerts
ELASTICSEARCH_LOGSTASH_ALERT_INDEX = ELASTICSEARCH_LOGSTASH_INDEX
# use hourly, daily to indicate the logstash index building recurrence
ELASTICSEARCH_LOGSTASH_TIMESTAMPING = "daily"
# Extension used for complete field (usually "raw" or "keyword")
ELASTICSEARCH_KEYWORD = "raw"
# Hostname field (usually "hostname" or "host")
ELASTICSEARCH_HOSTNAME = "host"
# Timestamp field (usually "@timestamp" or "timestamp")
ELASTICSEARCH_TIMESTAMP = "@timestamp"

# Kibana
USE_KIBANA = False
# Use django as a reverse proxy for kibana request
# This will allow you to use scirius authentication to control
# access to Kibana
KIBANA_PROXY = False
# Kibana URL
KIBANA_URL = "http://localhost:9292"
# Kibana index name
KIBANA_INDEX = "kibana-int"
# Path to Kibana's dashboards installation
KIBANA_DASHBOARDS_PATH = '/opt/kibana-dashboards/'
KIBANA6_DASHBOARDS_PATH = '/opt/kibana6-dashboards/'
KIBANA_ALLOW_GRAPHQL = True

USE_EVEBOX = False
EVEBOX_ADDRESS = "evebox:5636"

USE_CYBERCHEF = True
CYBERCHEF_URL = '/static/cyberchef/'

# Suricata is configured to write stats to EVE
USE_SURICATA_STATS = False
# Logstash is generating metrics on eve events
USE_LOGSTASH_STATS = False

# Set value to path to suricata unix socket to use suricatasc
# based info
SURICATA_UNIX_SOCKET = None
# SURICATA_UNIX_SOCKET = "/var/run/suricata/suricata-command.socket"

# Influxdb
USE_INFLUXDB = False
INFLUXDB_HOST = "localhost"
INFLUXDB_PORT = 8086
INFLUXDB_USER = "grafana"
INFLUXDB_PASSWORD = "grafana"
INFLUXDB_DATABASE = "scirius"

# Moloch
USE_MOLOCH = True
MOLOCH_URL = "https://localhost:8005"

# Proxy parameters
# Set USE_PROXY to True to use a proxy to fetch ruleset update.
# PROXY_PARAMS contains the proxy parameters.
# If user is set in PROXY_PARAMS then basic authentication will
# be used.
USE_PROXY = False
PROXY_PARAMS = {'http': "http://proxy:3128", 'https': "http://proxy:3128"}
# For basic authentication you can use
# PROXY_PARAMS = { 'http': "http://user:pass@proxy:3128", 'https': "http://user:pass@proxy:3128" }

GIT_SOURCES_BASE_DIRECTORY = os.path.join(BASE_DIR, 'git-sources/')

DBBACKUP_STORAGE = 'dbbackup.storage.filesystem_storage'
# DBBACKUP_STORAGE_OPTIONS = {'location': '/var/backups'}

# Ruleset generator framework
RULESET_MIDDLEWARE = 'suricata'
# Select transformation by copying the correct value to your loca_settings.py
# For IPS
RULESET_TRANSFORMATIONS = (('reject', 'Reject'), ('drop', 'Drop'), ('filestore', 'Filestore'))
# For an IDS with reject configured
# RULESET_TRANSFORMATIONS = (('reject', 'Reject'), ('filestore', 'Filestore'))
# For an IDS without reject
# RULESET_TRANSFORMATIONS = (('filestore', 'Filestore'),)

LOGIN_URL = '/accounts/login/'

IPWARE_PRIVATE_IP_PREFIX = ()

FILESTORE_SRC = '/var/log/suricata/filestore'

HAVE_NETINFO_AGG = False

try:
    from .local_settings import *  # noqa: F403, F401
except:
    pass

if KIBANA_PROXY:
    INSTALLED_APPS += ('revproxy',)
