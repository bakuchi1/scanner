from django.db import models

# Create your models here.
class PortList(models.Model):
    ip = models.CharField(max_length=50, verbose_name='ip', null=True)
    num = models.BigIntegerField(verbose_name='端口号')
    protocol = models.CharField(max_length=20,verbose_name='协议',blank=True,default='未知')
    status = models.CharField(default='open',max_length=10,verbose_name='状态',blank=True)
    class Meta:
        verbose_name=verbose_name_plural='端口列表'
        unique_together = ['ip', 'num']


class Domainlist(models.Model):
    name = models.CharField(max_length=100, unique=True)


class SubDomainlist(models.Model):
    domain = models.ForeignKey(Domainlist, on_delete=models.CASCADE)
    sub_name = models.CharField(max_length=100)