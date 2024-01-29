# Generated by Django 4.1.7 on 2023-11-16 13:56

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('userservice', '0012_alter_loginattempt_last_attempt_time'),
    ]

    operations = [
        migrations.CreateModel(
            name='OTPVerification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone_otp', models.CharField(max_length=6)),
                ('email_otp', models.CharField(max_length=6)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('attempts', models.IntegerField(default=0)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='otp', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]