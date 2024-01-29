from rest_framework import serializers
from .models import Users, OTPVerification  # Adjust the import according to your project structure

# User Serializer
class UsersSerializer(serializers.ModelSerializer):
    address = serializers.CharField(required=False)
    class Meta:
        model = Users
        fields = '__all__'
        
# Retrieve user Serializer
class RetrieveUserSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(required=False)
    email = serializers.CharField(required=False)
    class Meta:
        model = Users
        exclude = ('password',)

# OTPVerification Serializer
class OTPVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = OTPVerification
        fields = '__all__'