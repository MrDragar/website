# Generated by Django 3.2.2 on 2021-07-23 21:30

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Mine', '0004_players_web_tocken'),
    ]

    operations = [
        migrations.RenameField(
            model_name='players',
            old_name='web_tocken',
            new_name='web_token',
        ),
    ]
