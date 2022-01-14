from django.db import models


class Players(models.Model):
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

    class Meta:
        db_table = "Players"
# Create your models here.
