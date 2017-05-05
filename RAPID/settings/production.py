import os
from .base import *

BASE_SITE_URL = 'https://rapidpivot.com'
AMQP_URL = 'amqp://guest:guest@localhost:5672//'

ALLOWED_HOSTS = ['rapidpivot.com']

ADMINS = (('Name', 'email@service.com'),)

DEBUG = False
TEMPLATE_DEBUG = False

# SSL/TLS Settings
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
os.environ['wsgi.url_scheme'] = 'https'

# Email Settings
EMAIL_USE_TLS = True
EMAIL_HOST = retrieve_secret_configuration("EMAIL_HOST")
EMAIL_HOST_USER = retrieve_secret_configuration("EMAIL_USER")
EMAIL_HOST_PASSWORD = retrieve_secret_configuration("EMAIL_PASS")
EMAIL_PORT = retrieve_secret_configuration("EMAIL_PORT")

# TEMPLATE_DIRS += ("",)
# INSTALLED_APPS += ("",)

# Basic Logging Configuration
# https://docs.djangoproject.com/en/1.7/topics/logging/
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'RAPID.log',
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}