from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from .models import PortList, Domainlist, SubDomainlist

import time
import requests
import json, re
from django.views.decorators.csrf import csrf_exempt

# MYLOGGER = LogHandler(time.strftime("%Y-%m-%d", time.localtime()) + 'log')
# Create your views here.
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
}


@csrf_exempt
def port_scan(request):
    from .scan.portscan.portscan import ScanPort
    ip = request.POST.get('ip')
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(pattern, ip):
        result = ScanPort(ip).scan()
        for i in range(len(result)):
            if PortList.objects.filter(num=result[i].split(':')[1], ip=ip):
                pass
            else:
                PortList.objects.create(num=result[i].split(':')[1], protocol=result[i].split(':')[0], ip=ip)
        return success(200, result, 'ok')
    return error(400, 'please input correct IP address', 'error')


@csrf_exempt
def portscan(request):
    portlists = PortList.objects.all()
    return render(request, 'portscan.html', {'all_ports': portlists})


def delete_port(request):
    nid = request.GET.get('nid')
    PortList.objects.filter(id=nid).delete()
    return redirect('http://127.0.0.1:8000/portscan/')


@csrf_exempt
def get_subdomain(request):
    from .subdomains.subdomain import get_subdomain
    domain = request.POST.get('domain')
    if domain:
        result = get_subdomain(domain)
        print(result)
        try:
            domain = Domainlist.objects.get(name=domain)
            # Domain already exists, update its subdomains
            #existing_subdomains = set(domain.subdomain_set.all().values_list('sub_name', flat=True))
            #new_subdomains = set(result)

            #added_subdomains = new_subdomains - existing_subdomains
            #removed_subdomains = existing_subdomains - new_subdomains

            #for subdomain_name in added_subdomains:
            #    SubDomainlist.objects.create(domain=domain, sub_name=subdomain_name.strip())
            #for subdomain_name in removed_subdomains:
            #    domain.subdomain_set.filter(sub_name=subdomain_name.strip()).delete()
            return error(400, 'Please input correct domain or new domain', 'error')
        except Domainlist.DoesNotExist:
            # New domain, add both domain and subdomains
            domain = Domainlist.objects.create(name=domain)
            for subdomain_name in result:
                SubDomainlist.objects.create(domain=domain, sub_name=subdomain_name.strip())

            return success(200, result, 'ok')


def domain_list(request):
    domains = Domainlist.objects.all()
    return render(request, 'domainscan.html', {'domains': domains})


def subdomain_list(request):
    #domain = get_object_or_404(Domainlist, pk=domain_id)
    nid = request.GET.get('nid')
    subdomain = SubDomainlist.objects.filter(domain_id=nid)
    return render(request, 'subdomain.html', {'subdomains': subdomain})


def delete_domain(request):
    nid = request.GET.get('nid')
    Domainlist.objects.filter(id=nid).delete()
    SubDomainlist.objects.filter(domain_id=nid).delete
    return redirect('http://127.0.0.1:8000/domainscan/')


def success(code=200, data=[], msg='success'):
    result = {
        'code': code,
        'data': data,
        'msg': msg,
    }
    return HttpResponse(json.dumps(result), content_type='application/json')


def error(code=400, data=[], msg='error'):
    result = {
        'code': code,
        'data': data,
        'msg': msg,
    }
    return HttpResponse(json.dumps(result), content_type='application/json')
