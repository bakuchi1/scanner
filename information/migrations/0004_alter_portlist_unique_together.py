# Generated by Django 4.2.3 on 2023-08-13 21:50

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('information', '0003_remove_portlist_service_alter_portlist_status'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='portlist',
            unique_together={('ip', 'num')},
        ),
    ]
