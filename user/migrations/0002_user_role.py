# Generated by Django 5.2 on 2025-04-06 12:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('Admin', 'Admin'), ('User', 'User'), ('Staff', 'Staff'), ('Moderator', 'Moderator')], default='User', max_length=20),
        ),
    ]
