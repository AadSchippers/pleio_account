# -*- coding: utf-8 -*-
# Generated by Django 1.10.6 on 2017-09-26 07:36
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_auto_20170921_1548'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='is_persistent',
        ),
    ]
