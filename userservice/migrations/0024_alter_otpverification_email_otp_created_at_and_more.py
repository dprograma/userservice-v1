# Generated by Django 4.1.7 on 2024-01-14 00:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userservice', '0023_alter_otpverification_email_otp_created_at_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otpverification',
            name='email_otp_created_at',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
        migrations.AlterField(
            model_name='otpverification',
            name='phone_otp_created_at',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
    ]