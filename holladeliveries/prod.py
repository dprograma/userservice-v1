from .base import *
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '9&a#eib!x&na6_9m(fj0ad=2s__wa6+=*3gyfj#yw#m3y*pm$w'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

# [EMAIL]
MAIL_PORT = 587
MAIL_SERVER = "smtp.gmail.com"
MAIL_USER = "ketuojoken@gmail.com"
MAIL_PASS = "oyuisxthlkunofrk"

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "amapgsdb",
        "USER": "amapgs",
        "PASSWORD": "amapgs",
        "HOST": "localhost",  # Use the database service name from your Docker Compose file
        "PORT": 5432,
    },
}

