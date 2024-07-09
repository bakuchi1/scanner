from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render, redirect
from vulnscan.API import API
from django.views.decorators.csrf import csrf_exempt
import json, re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import time
from django.http import JsonResponse
# Create your views here.
# API_URL = 'https://127.0.0.1:3443'
# API_KEY = '1986ad8c0a5b3df4d7028d5f3c06e936cf7ec4b29d6404aec9733c4a5e1df5b73'

def vulnscan(request):
    data = API.get_all_scan()
    data_list = []
    for count, msg in enumerate(data,start=0):
        current_session = msg['current_session']
        table_data = {
            'id': count + 1,
            'status': current_session['status'],
            'target_id': msg['target_id'],
            'target': msg['target']['address'],
            'scan_type': msg["profile_name"],
            'vuln': current_session['severity_counts'],
            'plan': re.sub(r'T|\..*$', " ", current_session['start_date'])
        }
        data_list.append(table_data)
    return render(request, "vulnscan.html", {"data": data_list})


@csrf_exempt
def add_scan(request):
    url = request.POST.get('ip')
    scan_type = request.POST.get('scan_type')
    result = API.add_target(url)
    target_id = result.get('target_id')
    #print(target_id)
    if target_id is not None:
        status_code = API.add_scan(target_id, scan_type)
        if status_code == 200:
            return success()
    return error()


def vuln_result(request,target_id):
    data_list = []
    vuln_details = json.loads(API.search_result("open", target_id=str(target_id)))
    for count, target in enumerate(vuln_details['vulnerabilities'], start=1):
        item = {
            'id': id,
            'severity': target['severity'],
            'target': target['affects_url'],
            'vuln_id': target['vuln_id'],
            'vuln_name': target['vt_name'],
            'time': re.sub(r'T|\..*$', " ", target['last_seen'])
        }
        data_list.append(item)
    return render(request, 'vuln_result.html', {'data': data_list})

def dashboard(request):
    data = API.get_all_scan()
    data_list = []
    for count, msg in enumerate(data, start=0):
        current_session = msg['current_session']
        table_data = {
            'id': count + 1,
            'status': current_session['status'],
            'target_id': msg['target_id'],
            'target': msg['target']['address'],
            'scan_type': msg["profile_name"],
            'vuln': current_session['severity_counts'],
            'plan': re.sub(r'T|\..*$', " ", current_session['start_date'])
        }
        data_list.append(table_data)
    xss = 0
    sqlinj = 0
    dl = 0
    ht = 0
    el = 0
    for item in data:
        target_id = item['target_id']
        vuln_details = json.loads(API.search_result("open", target_id=str(target_id)))
        for target in vuln_details['vulnerabilities']:
            if target['vt_name'] == 'Cross site scripting':
                xss += 1
            elif target['vt_name'] == 'SQL injection':
                sqlinj += 1
            elif target['vt_name'] == 'Directory listing':
                dl += 1
            elif target['vt_name'] == 'HTML form without CSRF protection':
                ht += 1
            else:
                el += 1
    vulns = [xss, sqlinj, dl, ht, el]
    return render(request, 'dashboard.html', {'data': data_list, 'vulns' : vulns})


def get_target_id():
    data = API.get_all_scan()
    target_list = []
    for target in data:
        target_list.append(target['target_id'])
    return target_list


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
def vuln_detail(request,vuln_id):
    data = API.get_detail_vuln(vuln_id)
    #print(data)
    parameter_list = BeautifulSoup(data['details'], features="html.parser").findAll('span')
    request_list = BeautifulSoup(data['details'], features="html.parser").findAll('li')
    data_dict = {
        'affects_url': data['affects_url'],
        'last_seen': re.sub(r'T|\..*$', " ", data['last_seen']),
        'vt_name': data['vt_name'],
        'details': data['details'].replace("  ",'').replace('</p>',''),
        'request': data['request'],
        'recommendation': data['recommendation'].replace('<br/>','\n')
    }
    parameter_name = parameter_data = ''
    if len(parameter_list) >= 2:
        parameter_name = parameter_list[0].contents[0]
        parameter_data = parameter_list[1].contents[0]

    tests_performed = ''
    for request_item in request_list:
        tests_performed += f"{request_item.contents[0]}{request_item.contents[1].text.replace('<strong>', '').replace('</strong>', '')}\n"

    data_dict['parameter_name'] = parameter_name
    data_dict['parameter_data'] = parameter_data
    data_dict['Tests_performed'] = tests_performed
    data_dict['num'] = len(request_list)
    data_dict['details'] = data_dict['details'].replace('class="bb-dark"', 'style="color: #ff0000"')
    return render(request, "vuln_details.html", {'data': data_dict})


def get_vuln_id():
    data = API.get_all_vuln("open")
    vuln_list = [vuln['vuln_id'] for vuln in data.get('vulnerabilities', [])]
    return vuln_list


@csrf_exempt
def get_vuln_rank(request):
    data = API.dashboard()["top_vulnerabilities"]
    vuln_rank = [{'name': item['name'], 'value': item['count']} for item in data[:5]]
    return JsonResponse(vuln_rank, safe=False)


@csrf_exempt
def get_vuln_value(request):
    data = API.dashboard()["vuln_count_by_criticality"]
    result = {}
    if data['high'] is not None:
        result['high'] = list(data['high'].values())
    if data['normal'] is not None:
        result['normal'] = list(data['normal'].values())
    return JsonResponse(result, safe=False)


