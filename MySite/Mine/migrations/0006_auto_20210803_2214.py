# Generated by Django 3.2.2 on 2021-08-03 22:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Mine', '0005_rename_web_tocken_players_web_token'),
    ]

    operations = [
        migrations.AddField(
            model_name='players',
            name='nickname_token',
            field=models.CharField(default='', max_length=32),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='players',
            name='password_token',
            field=models.CharField(default='', max_length=32),
            preserve_default=False,
        ),
    ]
