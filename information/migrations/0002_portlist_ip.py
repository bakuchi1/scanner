# Generated by Django 4.2.3 on 2023-07-29 15:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('information', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='portlist',
            name='ip',
            field=models.CharField(max_length=50, null=True, verbose_name='ip'),
        ),
    ]
