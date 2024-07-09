from django.db import models

# Create your models here.
class User(models.Model):
    name=models.CharField(verbose_name='username', max_length=32)
    email=models.CharField(verbose_name='email', max_length=64)
    password=models.CharField(verbose_name='password', max_length=64)

