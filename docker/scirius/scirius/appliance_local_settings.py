# Copyright(C) 2020, Gabor Seljan
# Copyright(C) 2021, Stamus Networks
#
# Adapted by Raphael Brogat <rbrogat@stamus-networks.com>
#
# This script comes with ABSOLUTELY NO WARRANTY!
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Django settings for the Scirius project.
"""

import contextlib
import os


def strtobool(val):
    """Convert a string representation of truth to True or False."""
    val = str(val).lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return True
    if val in ('n', 'no', 'f', 'false', 'off', '0'):
        return False
    raise ValueError(f"Invalid truth value: {val}")


# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = bool(strtobool(os.getenv('DEBUG', '0')))

# SECURITY WARNING: don't use '*' in production!
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost 127.0.0.1 [::1]').split(' ')

# 127.0.0.1 must be allowed for container health checking
if '127.0.0.1' not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append('127.0.0.1')

# Logging
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
        'celeryformat': {
            'format': '%(asctime)s %(processName)s %(levelname)s %(message)s'
        }
    },
    'handlers': {
        'elasticsearch': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/logs/elasticsearch.log',
            'formatter': 'raw',
        },
        'task_error': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/logs/worker-error.log',
            'formatter': 'raw',
        },
        'error_log': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/logs/django-error.log',
            'formatter': 'fileformat',
        },
        'auth_log': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/logs/django-auth.log',
            'formatter': 'fileformat',
        },
        'celery_tasks': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/logs/celery_tasks.log',
            'formatter': 'celeryformat',
        },
    },
    'loggers': {
        'elasticsearch': {
            'handlers': ['elasticsearch'],
            'level': 'INFO',
            'propagate': False,
        },
        'task_logger': {
            'handlers': ['task_error'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['error_log'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'authentication': {
            'handlers': ['auth_log'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'celery_tasks': {
            'handlers': ['celery_tasks'],
            'level': 'DEBUG',
            'propagate': False,
        },

    }
}

# Scirius
SCIRIUS_HAS_DOC = True

# Internationalization
LANGUAGE_CODE = os.getenv('LANGUAGE_CODE', 'en-us')
TIME_ZONE = os.getenv('TIME_ZONE', 'UTC')

# Static files
STATIC_URL = os.getenv('STATIC_URL', '/static/')
STATIC_ROOT = os.getenv('STATIC_ROOT', '/static')
STATIC_AUTHENTICATED = bool(strtobool(os.getenv('STATIC_AUTHENTICATED', '0')))

# Suricata
SURICATA_UNIX_SOCKET = os.getenv('SURICATA_UNIX_SOCKET', '/var/run/suricata.socket')
SURICATA_NAME_IS_HOSTNAME = bool(strtobool(os.getenv('SURICATA_NAME_IS_HOSTNAME', '0')))

# Elasticsearch
USE_DATA_LIKE = os.getenv('USE_DATA_LIKE', 'OPENSEARCH_2')
ELASTICSEARCH_VERIFY_CERTS = bool(strtobool(os.getenv('ELASTICSEARCH_VERIFY_CERTS', '1')))
ELASTICSEARCH_ADDRESS = os.getenv('ELASTICSEARCH_ADDRESS', 'elasticsearch:9200')
ELASTICSEARCH_LOGSTASH_INDEX = os.getenv('ELASTICSEARCH_LOGSTASH_INDEX', 'logstash-')
ELASTICSEARCH_LOGSTASH_INDEX_INJECTED = os.getenv('ELASTICSEARCH_LOGSTASH_INDEX_INJECTED', 'logstash-')
ELASTICSEARCH_LOGSTASH_ALERT_INDEX = os.getenv('ELASTICSEARCH_LOGSTASH_ALERT_INDEX', 'logstash-alert-')
ELASTICSEARCH_LOGSTASH_TIMESTAMPING = os.getenv('ELASTICSEARCH_LOGSTASH_TIMESTAMPING', 'daily')
ELASTICSEARCH_KEYWORD = os.getenv('ELASTICSEARCH_KEYWORD', 'keyword')
ELASTICSEARCH_HOSTNAME = os.getenv('ELASTICSEARCH_HOSTNAME', 'host')
ELASTICSEARCH_TIMESTAMP = os.getenv('ELASTICSEARCH_TIMESTAMP', '@timestamp')

# Kibana
USE_KIBANA = bool(strtobool(os.getenv('USE_KIBANA', '0')))
KIBANA_PROXY = bool(strtobool(os.getenv('KIBANA_PROXY', '0')))
KIBANA_URL = os.getenv('KIBANA_URL', 'http://kibana:5601')
KIBANA_INDEX = os.getenv('KIBANA_INDEX', '.kibana')
KIBANA_DASHBOARDS_PATH = os.getenv('KIBANA_DASHBOARDS_PATH', '/opt/kibana-dashboards/')
KIBANA6_DASHBOARDS_PATH = os.getenv('KIBANA6_DASHBOARDS_PATH', '/opt/kibana6-dashboards/')
KIBANA7_DASHBOARDS_PATH = os.getenv('KIBANA6_DASHBOARDS_PATH', '/opt/kibana7-dashboards/')
KIBANA_ALLOW_GRAPHQL = bool(strtobool(os.getenv('KIBANA_ALLOW_GRAPHQL', '1')))

# EveBox
USE_EVEBOX = bool(strtobool(os.getenv('USE_EVEBOX', '0')))
EVEBOX_ADDRESS = os.getenv('EVEBOX_ADDRESS', 'http://evebox:5636')
USE_SURICATA_STATS = bool(strtobool(os.getenv('USE_SURICATA_STATS', '0')))
USE_LOGSTASH_STATS = bool(strtobool(os.getenv('USE_LOGSTASH_STATS', '0')))

# CyberChef
USE_CYBERCHEF = bool(strtobool(os.getenv('USE_CYBERCHEF', '1')))
CYBERCHEF_URL = os.getenv('CYBERCHEF_URL', '/static/cyberchef/')

# Moloch
USE_MOLOCH = bool(strtobool(os.getenv('USE_MOLOCH', '0')))
MOLOCH_URL = os.getenv('MOLOCH_URL', 'http://moloch:8005')

# Proxy settings
USE_PROXY = bool(strtobool(os.getenv('USE_PROXY', '0')))
HTTP_PROXY = os.getenv('HTTP_PROXY', 'http://proxy:3128')
HTTPS_PROXY = os.getenv('HTTPS_PROXY', 'http://proxy:3128')
PROXY_PARAMS = {'http': HTTP_PROXY, 'https': HTTPS_PROXY}

# Content Security Policy settings
CSP_DEFAULT_SRC = tuple(os.getenv('CSP_DEFAULT_SRC', "'self'").split(' '))
CSP_SCRIPT_SRC = tuple(os.getenv('CSP_SCRIPT_SRC', "'self' 'unsafe-inline'").split(' '))
CSP_STYLE_SRC = tuple(os.getenv('CSP_STYLE_SRC', "'self' 'unsafe-inline'").split(' '))
CSP_INCLUDE_NONCE_IN = os.getenv('CSP_INCLUDE_NONCE_IN', 'script-src').split(' ')
CSP_EXCLUDE_URL_PREFIXES = tuple(os.getenv('CSP_EXCLUDE_URL_PREFIXES', '/evebox /mcp').split(' '))

GIT_SOURCES_BASE_DIRECTORY = '/data/git-sources/'

SCIRIUS_VERSION = "0.9.0"
LOGO = 'rules/stamus.png'

ENGINE = "django.db.backends.postgresql"
NAME = os.getenv('DATABASE_NAME', 'db.sqlite3')
USER = os.getenv('DATABASE_USERNAME', '')
PASSWORD = os.getenv('DATABASE_PASSWORD', '')
HOST = os.getenv('DATABASE_HOST', '')
PORT = os.getenv('DATABASE_PORT', '')

DATABASES = {
    'default': {
        'ENGINE': ENGINE,
        'NAME': NAME,
        'USER': USER,
        'PASSWORD': PASSWORD,
        'HOST': HOST,
        'PORT': PORT,
    }
}


RULESET_MIDDLEWARE = os.getenv('RULESET_MIDDLEWARE', 'appliances')

USE_OPENSEARCH = True

CELERY_BROKER = os.getenv("CELERY_BROKER", 'amqp://guest:guest@rabbitmq:5672//')
CELERY_RESULT_BACKEND = f'db+postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{NAME}'

CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:8000",
    "http://localhost:5173",
]


# CORS_ALLOWED_ORIGINS = [
#     "*",
# ]
CORS_ALLOW_CREDENTIALS = True
CORS_ORIGIN_ALLOW_ALL = True

CORS_ALLOW_HEADERS = ["authorization", "cookies", "withcredentials", "content-type"]

CORS_ALLOWED_ORIGINS = [
    'http://localhost:5173',
    'http://localhost:8000',
    'http://localhost',
    'https://localhost',
    os.getenv('HTTP_HOST', "http://localhost:8000"),
    os.getenv('STATIC_URL', "http://localhost:3001"),
    os.getenv('FRONT_URL', "http://localhost:3002")
]

ANSIBLE_BASE_DIR = "/ansible"
ANSIBLE_PATH = "ansible"
USE_ANSIBLE_TO_GET_MAC = False


class DATA_LIKE:
    ES_6 = 'ELASTICSEARCH_6'
    ES_7 = 'ELASTICSEARCH_7'
    ES_8 = 'ELASTICSEARCH_8'
    OS_1 = 'OPENSEARCH_1'
    OS_2 = 'OPENSEARCH_2'


USE_DATA_LIKE = DATA_LIKE.OS_2

# Appliance specific settings
GPG_SEE_PASSPHRASE = 'xG3jVHnwhEA4tPJfBqgH'  # noqa: S105
GPG_SEE_MAIL = 'unique-id@stamus-networks.com'
PASSIVE_PROBE_TIMEOUT = 20  # minutes
UNIQUE_ID_FILE = 'SEE-unique-id.tar.gz.gpg'
STAMUS_TI_URL = 'https://ti.stamus-networks.io/%s/'
THREAT_SOURCE = os.path.join(STAMUS_TI_URL, 'stamus/str/threats.tar.gz')
THREAT_ETPRO_SOURCE = os.path.join(STAMUS_TI_URL, 'stamus/str-etpro/threats%s.tar.gz')
ETPRO_SOURCE = os.path.join(STAMUS_TI_URL, 'etpro/suricata-7.0.3/etpro.rules.tar.gz')
MAX_NB_ITEMS_PER_POST = 1000

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
    'appliances.config.AppliancesConfig',
    'django_celery_results',
    'accounts',
    'volumetry',
    'rest_framework',
    'rest_framework.authtoken',
    'django_filters',
    'webpack_loader',
    'chunked_upload',
    'django_ace',
    'djangosaml2',
    'mcp_server',
)

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
    'scirius.utils.CustomCSPMiddleware',
    'django_cprofile_middleware.middleware.ProfilerMiddleware',
    'djangosaml2.middleware.SamlSessionMiddleware'
]


GENERATED_BASE_DIR = '/var/lib/scirius-pro/'
UPGRADE_BASE_DIR = f'{GENERATED_BASE_DIR}upgrade/'
GIT_SOURCES_BASE_DIRECTORY = f'{GENERATED_BASE_DIR}git-sources/'
GIT_RULESETS_BASE_DIRECTORY = f'{GENERATED_BASE_DIR}git-rulesets/'
VPN_CERT_PATH = f'{GENERATED_BASE_DIR}openvpn/pki/'
NOTEBOOKS_DEST = f'{GENERATED_BASE_DIR}reporting'
FILESTORE_DEST = f'{GENERATED_BASE_DIR}filestore'
PCAPS_FILESTORE_DEST = f'{GENERATED_BASE_DIR}pcaps'
SAML_IDP_DEST = f'{GENERATED_BASE_DIR}saml'
FLOCK_PATH = os.path.join(GENERATED_BASE_DIR, 'lock')

LOGSTASH_CIDR_RANGE = '192.0.2.2/32'

SSH_KEY_ABSOLUTE_PATH = '/var/www/.ssh/id_rsa'
USE_GO_POSTPROC_TEST_CONF = False

BOOTSTRAP3 = {
    'field_renderers': {
        'default': 'bootstrap3.renderers.FieldRenderer',
        'inline': 'bootstrap3.renderers.InlineFieldRenderer',
        'template': 'appliances.views.templates.TemplateFieldRenderer'
    }
}

with contextlib.suppress(ImportError, NameError):
    from .authentication import *  # type: ignore # noqa: F403, F401
