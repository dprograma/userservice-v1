from .base import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '9&a#eib!x&na6_9m(fj0ad=2s__wa6+=*3gyfj#yw#m3y*pm$w'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# Always use IPython for shell_plus
SHELL_PLUS = "ipython"

CORS_ALLOW_ALL_ORIGINS = True

CURRENT_SITE = "http://127.0.0.1:8001"
CLIENT_SITE = "http://127.0.0.1:3000"

TEST_PHONE_NUMBER = "2348160093332"
TERMII_PHONE_OTP_URL = "https://termii.com/api/sms/send"
TERMII_API_KEY = "TL62g0ZDHddgdbTZLXYosd6834pHqTWB5MG2EkZquN0L7OsoC2QmSYqpfQJAMm"



# [EMAIL]
MAIL_PORT = 465
MAIL_SERVER = "sandbox.smtp.mailtrap.io"
MAIL_USER = "e4ddb8cd5d0f6e"
MAIL_PASS = "7c789e78d8ef2a"
