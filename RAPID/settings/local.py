from .base import *

DEBUG = True
TEMPLATE_DEBUG = True

CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False

AMQP_URL = 'amqp://guest:guest@localhost:5672//'

BASE_SITE_URL = 'http://0.0.0.0:8000'

EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

ALLOWED_HOSTS = []

# TEMPLATE_DIRS += ("",)
# INSTALLED_APPS += ("",)

# Basic Logging Configuration
# https://docs.djangoproject.com/en/1.7/topics/logging/
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'RAPID.log',
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}