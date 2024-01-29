from datetime import timedelta
import datetime
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.db.models import F

from .constants import MAX_LOGIN_ATTEMPTS


class Users(AbstractUser):
    phone_number = models.CharField(max_length=20, unique=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    username = models.CharField(max_length=255, null=True, blank=True)
    email = models.CharField(max_length=255, unique=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    last_login_user_agent = models.TextField(null=True, blank=True)
    is_locked = models.BooleanField(default=False)
    avatar = models.ImageField(
        upload_to="profile/", default="profile/avatar.png", null=True, blank=True
    )
    # Override any methods or add custom methods to the model as needed
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["firstname", "lastname", "phone_number"]

    class Meta:
        app_label = "userservice"

    def __str__(self):
        return self.username


class LoginAttempt(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)
    attempts = models.PositiveIntegerField(default=0)
    last_attempt_time = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    lockout_duration = models.DurationField(default=timedelta(seconds=900))
    max_login_attempts = models.PositiveIntegerField(default=MAX_LOGIN_ATTEMPTS)

    user = models.ForeignKey(
        Users,
        on_delete=models.CASCADE,
        related_name="login_attempts",
        null=True,
        blank=True,
    )

    class Meta:
        app_label = "userservice"

    @classmethod
    def lock_user(cls, ip_address):
        Users.objects.filter(last_login_ip=ip_address).update(is_locked=True)

    @classmethod
    def add_attempt(cls, ip_address):
        """Add a login attempt for the given IP address."""
        user = Users.objects.filter(last_login_ip=ip_address).first()

        attempt, created = cls.objects.get_or_create(
            ip_address=ip_address, defaults={"user": user, "attempts": 1, "last_attempt_time": timezone.now()})

        if not created:
            # If a record already exists, update it
            cls.objects.filter(ip_address=ip_address).update(user=user, attempts=F("attempts") + 1, last_attempt_time=timezone.now())
            attempt.refresh_from_db()
            
            

    @classmethod
    def get_attempts(cls, ip_address):
        """Get the number of login attempts for the given IP address."""
        try:
            login_attempts = cls.objects.get(ip_address=ip_address)
        except LoginAttempt.DoesNotExist:
            return 0
        if login_attempts.attempts:
            return login_attempts.attempts
        return 0

    @classmethod
    def reset_attempts(cls, ip_address=None):
        """Reset the login attempts for the given IP address."""
        cls.objects.filter(ip_address=ip_address).update(
            attempts=0, last_attempt_time=timezone.now()
        )
        Users.objects.filter(last_login_ip=ip_address).update(is_locked=False)

    @classmethod
    def is_ip_locked(cls, ip_address=None):
        """
        Check if the IP address is locked due to too many login attempts.
        """
        try:
            login_attempts = cls.objects.get(ip_address=ip_address)
        except LoginAttempt.DoesNotExist:
            # If no record exists for this IP, we can assume it's not locked
            return False

        if login_attempts and login_attempts.attempts >= MAX_LOGIN_ATTEMPTS:
            time_difference = timezone.now() - login_attempts.last_attempt_time
            # result = time_difference <= login_attempts.lockout_duration
            return time_difference <= login_attempts.lockout_duration
        else:
            return False


class OTPVerification(models.Model):
    user = models.ForeignKey(Users, related_name="otp", on_delete=models.CASCADE)
    phone_otp = models.CharField(max_length=6, null=True, blank=True)
    email_otp = models.CharField(max_length=6, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    phone_otp_created_at = models.DateTimeField(auto_now=True, null=True, blank=True)
    email_otp_created_at = models.DateTimeField(auto_now=True, null=True, blank=True)
    attempts = models.IntegerField(default=0)

    class Meta:
        app_label = "userservice"

    def is_expired(self):
        # Set OTP expiry time (e.g., 5 minutes from creation)
        expiry_duration = datetime.timedelta(minutes=5)
        return timezone.now() > self.phone_otp_created_at + expiry_duration or timezone.now() > self.email_otp_created_at + expiry_duration

    def set_user_is_active(self, id):
        # grab the current user from Users model use the user instance from OTPVerification model
        current_user = Users.objects.get(id=id)
        # set current user status to is_active
        current_user.is_active = True
        # save current user
        current_user.save()
