from rest_framework import serializers

class LoginSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=100)

class VerifySerializer(serializers.Serializer):
    session_key = serializers.CharField(max_length=100)