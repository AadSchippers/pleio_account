# -*- coding: utf-8 -*-
# Generated by Django 1.10.6 on 2017-10-19 08:50
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0007_previous_logins'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='previous_logins',
            name='location',
        ),
    ]
