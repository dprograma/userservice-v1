# Generated by Django 4.1.7 on 2024-01-11 13:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userservice', '0021_alter_loginattempt_last_attempt_time'),
    ]

    operations = [
        migrations.AddField(
            model_name='otpverification',
            name='email_otp_created_at',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
        migrations.AddField(
            model_name='otpverification',
            name='phone_otp_created_at',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
    ]
