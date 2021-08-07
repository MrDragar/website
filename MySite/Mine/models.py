from django.db import models


class players(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=16)
    password = models.CharField(max_length=32)
    uuid = models.CharField(max_length=32)
    accessToken = models.CharField(max_length=32)
    serverID = models.CharField(max_length=42)
    email = models.CharField(max_length=40)
    verification = models.BooleanField()
    web_token = models.CharField(max_length=32)
    password_token = models.CharField(max_length=32)
    nickname_token = models.CharField(max_length=32)


class versions(models.Model):
    id = models.AutoField(primary_key=True)
    number = models.CharField(max_length=16)
    changes = models.CharField(max_length=500)
