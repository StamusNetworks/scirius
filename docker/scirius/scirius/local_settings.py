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

import os
from distutils.util import strtobool
from kombu import Exchange, Queue, binding  # noqa: E402


APP_LONG_NAME = os.getenv('APP_LONG_NAME', 'Scirius Community Edition')
APP_MEDIUM_NAME = os.getenv('APP_MEDIUM_NAME', 'Scirius CE')
APP_SHORT_NAME = os.getenv('APP_SHORT_NAME', APP_MEDIUM_NAME)
APP_MNGT_NAME = os.getenv('APP_MNGT_NAME', 'Clear NDR CE Management')
PRODUCT_LONG_NAME = os.getenv('PRODUCT_LONG_NAME', 'Clear NDR Community Edition')
PRODUCT_SHORT_NAME = os.getenv('PRODUCT_SHORT_NAME', 'Clear NDR')
PRODUCT_MEDIUM_NAME = os.getenv('PRODUCT_MEDIUM_NAME', 'Clear NDR CE')
LOGO = os.getenv('LOGO', 'rules/selks.png')

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
    'django_celery_results',
    'accounts',
    'rest_framework',
    'rest_framework.authtoken',
    'django_filters',
    'webpack_loader',
    'chunked_upload',
    'django_ace',
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
    'django_cprofile_middleware.middleware.ProfilerMiddleware'
]

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
            'propagate': True,
        },
        'task_logger': {
            'handlers': ['task_error'],
            'level': 'INFO',
            'propagate': True,
        },
        'django.request': {
            'handlers': ['error_log'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'authentication': {
            'handlers': ['auth_log'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'celery_tasks': {
            'handlers': ['celery_tasks'],
            'level': 'DEBUG',
            'propagate': True,
        },

    }
}

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
USE_ELASTICSEARCH = bool(strtobool(os.getenv('USE_ELASTICSEARCH', '0')))
ELASTICSEARCH_ADDRESS = os.getenv('ELASTICSEARCH_ADDRESS', 'elasticsearch:9200')
ELASTICSEARCH_LOGSTASH_INDEX = os.getenv('ELASTICSEARCH_LOGSTASH_INDEX', 'logstash-')
ELASTICSEARCH_LOGSTASH_ALERT_INDEX = os.getenv('ELASTICSEARCH_LOGSTASH_ALERT_INDEX', 'logstash-alert-')
ELASTICSEARCH_LOGSTASH_TIMESTAMPING = os.getenv('ELASTICSEARCH_LOGSTASH_TIMESTAMPING', 'daily')
ELASTICSEARCH_KEYWORD = os.getenv('ELASTICSEARCH_KEYWORD', 'keyword')
ELASTICSEARCH_HOSTNAME = os.getenv('ELASTICSEARCH_HOSTNAME', 'host')
ELASTICSEARCH_TIMESTAMP = os.getenv('ELASTICSEARCH_TIMESTAMP', '@timestamp')

# Kibana
USE_KIBANA = bool(strtobool(os.getenv('USE_KIBANA', '0')))
KIBANA_PROXY = bool(strtobool(os.getenv('KIBANA_PROXY', '0')))

# EveBox
USE_EVEBOX = bool(strtobool(os.getenv('USE_EVEBOX', '0')))
USE_SURICATA_STATS = bool(strtobool(os.getenv('USE_SURICATA_STATS', '0')))
USE_LOGSTASH_STATS = bool(strtobool(os.getenv('USE_LOGSTASH_STATS', '0')))

CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:8000",
    "http://localhost:5173",
]

# Content Security Policy settings
CSP_DEFAULT_SRC = tuple(os.getenv('CSP_DEFAULT_SRC', "'self'").split(' '))
CSP_SCRIPT_SRC = tuple(os.getenv('CSP_SCRIPT_SRC', "'self' 'unsafe-inline'").split(' '))
CSP_STYLE_SRC = tuple(os.getenv('CSP_STYLE_SRC', "'self' 'unsafe-inline'").split(' '))
CSP_INCLUDE_NONCE_IN = os.getenv('CSP_INCLUDE_NONCE_IN', 'script-src').split(' ')
CSP_EXCLUDE_URL_PREFIXES = tuple(os.getenv('CSP_EXCLUDE_URL_PREFIXES', '/evebox').split(' '))

GENERATED_BASE_DIR = '/data/'
FLOCK_PATH = f'{GENERATED_BASE_DIR}lock'
GIT_SOURCES_BASE_DIRECTORY = f'{GENERATED_BASE_DIR}git-sources/'
GIT_SOURCES_BASE_DIRECTORY = f'{GENERATED_BASE_DIR}git-rulesets/'

RULESET_MIDDLEWARE = os.getenv('RULESET_MIDDLEWARE', 'suricata')

USE_OPENSEARCH = True
HAVE_NETINFO_AGG = False

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

SURICATA_OUTPUT_DIRECTORY = '/rules'

exchange = Exchange('celery', type='direct')
CELERY_QUEUES = [Queue('celery', [
    binding(exchange, routing_key='celery'),
])]

KIBANA_ALLOW_GRAPHQL = bool(strtobool(os.getenv('KIBANA_ALLOW_GRAPHQL', '1')))
