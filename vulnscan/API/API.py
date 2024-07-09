from logging.config import fileConfig
import requests
import logging
from os import path

'''API urls'''


def API_url():
    # API_URL = 'https://127.0.0.1:3443'
    API_KEY = '1986ad8c0a5b3df4d7028d5f3c06e936cf7ec4b29d6404aec9733c4a5e1df5b73'
    # api_base_url = API_URL.strip('/')
    targets_api = 'https://127.0.0.1:3443/api/v1/targets'
    scan_api = 'https://127.0.0.1:3443/api/v1/scans'
    vuln_api = 'https://127.0.0.1:3443/api/v1/vulnerabilities'
    report_api = 'https://127.0.0.1:3443/api/v1/reports'
    create_group_api = 'https://127.0.0.1:3443/api/v1/target_groups'
    dashboard_api = 'https://127.0.0.1:3443//api/v1/me/stats'
    auth_headers = {
        'X-Auth': API_KEY,
        'content-type': 'application/json'
    }
    requests.packages.urllib3.disable_warnings()
    api = [targets_api, scan_api, vuln_api, report_api, create_group_api, auth_headers,dashboard_api]
    return api


'''add_target'''


def add_target(address, description=None):
    api = API_url()
    # targets_api = 'https://127.0.0.1:3443/api/v1/targets'
    description = description or f'{address} test'
    data = {
        'address': address,
        'description': description,
    }
    try:
        response = requests.post(
            api[0], headers=api[5], json=data, verify=False
        )
        result = response.json()
        # print(result)
        return result
    except Exception:
        return None


'''add_scan'''


def add_scan(target_id, scan_type, schedule=None):
    scan_type_dict = {
        'full_scan': '11111111-1111-1111-1111-111111111111',
        'xss_vuln': '11111111-1111-1111-1111-111111111116',
        'sqli_vuln': '11111111-1111-1111-1111-111111111113',
        'weak_passwords': '11111111-1111-1111-1111-111111111115',
    }
    api = API_url()
    data = {
        'target_id': target_id,
        'profile_id': scan_type_dict.get(scan_type),
        'schedule': schedule or {
            'disable': False,
            'start_date': None,
            'time_sensitive': False
        }
    }
    try:
        response = requests.post(
            api[1], json=data, headers=api[5], verify=False
        )
        status_code = 200
    except Exception:
        status_code = 404
    return status_code


def get_all_scan():
    api = API_url()
    try:
        response = requests.get(api[1], headers=api[5], verify=False)
        scan_response = response.json().get('scans', [])
        request_url = response.url
        scan_list = [{'request_url': request_url, **scan} for scan in scan_response]
    except Exception:
        scan_list = []
    return scan_list


'''vul_result'''


def search_result(status, target_id=None):
    api = API_url()
    vuln_search_api = f'{api[2]}?q=status:{status};target_id:{target_id}'
    # print(vuln_search_api)
    try:
        response = requests.get(vuln_search_api, headers=api[5], verify=False)
        # print(response.text)
        return response.text
    except Exception:
        return None


def get_detail_vuln(vuln_id):
    api = API_url()
    vuln_get_api = f'{api[2]}/{vuln_id}'
    try:
        response = requests.get(vuln_get_api, headers=api[5], verify=False)
        return response.json()
    except Exception:
        return None


def get_all_vuln(status):
    api = API_url()
    try:
        response = requests.get(f'{api[2]}?q=status:{status}', headers=api[5], verify=False)
        return response.json()
    except Exception:
        return None

'''dashboard'''


def dashboard():
    api = API_url()
    try:
        response = requests.get(api[6], headers=api[5], verify=False)
        return response.json()
    except Exception:
        return None
