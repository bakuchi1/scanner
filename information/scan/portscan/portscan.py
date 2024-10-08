# -*- coding:utf-8 -*-

# Reference: https://github.com/jwt1399/Sec-Tools/blob/master/webscan_backend/plugins/portscan/portscan.py

import socket
import re
import concurrent.futures
import sys
import os
from urllib import parse

sys.path.append(os.getcwd())

THREADNUM = 64

SIGNS = [
    'http|^HTTP.*',
    'ssh|SSH-2.0-OpenSSH.*',
    'ssh|SSH-1.0-OpenSSH.*',
    'netbios|^\x79\x08.*BROWSE',
    'netbios|^\x79\x08.\x00\x00\x00\x00',
    'netbios|^\x05\x00\x0d\x03',
    'netbios|^\x83\x00',
    'netbios|^\x82\x00\x00\x00',
    'netbios|\x83\x00\x00\x01\x8f',
    'backdoor-fxsvc|^500 Not Loged in',
    'backdoor-shell|GET: command',
    'backdoor-shell|sh: GET:',
    'bachdoor-shell|[a-z]*sh: .* command not found',
    'backdoor-shell|^bash[$#]',
    'backdoor-shell|^sh[$#]',
    'backdoor-cmdshell|^Microsoft Windows .* Copyright .*>',
    'db2|.*SQLDB2RA',
    'db2jds|^N\x00',
    'dell-openmanage|^\x4e\x00\x0d',
    'finger|^\r\n	Line	  User',
    'finger|Line	 User',
    'finger|Login name: ',
    'finger|Login.*Name.*TTY.*Idle',
    'finger|^No one logged on',
    'finger|^\r\nWelcome',
    'finger|^finger:',
    'finger|^must provide username',
    'finger|finger: GET: ',
    'ftp|^220.*\n331',
    'ftp|^220.*\n530',
    'ftp|^220.*FTP',
    'ftp|^220 .* Microsoft .* FTP',
    'ftp|^220 Inactivity timer',
    'ftp|^220 .* UserGate',
    'http|^HTTP/0.',
    'http|^HTTP/1.',
    'http|<HEAD>.*<BODY>',
    'http|<HTML>.*',
    'http|<html>.*',
    'http|<!DOCTYPE.*',
    'http|^Invalid requested URL ',
    'http|.*<?xml',
    'http|^HTTP/.*\nServer: Apache/1',
    'http|^HTTP/.*\nServer: Apache/2',
    'http-iis|.*Microsoft-IIS',
    'http-iis|^HTTP/.*\nServer: Microsoft-IIS',
    'http-iis|^HTTP/.*Cookie.*ASPSESSIONID',
    'http-iis|^<h1>Bad Request .Invalid URL.</h1>',
    'http-jserv|^HTTP/.*Cookie.*JServSessionId',
    'http-tomcat|^HTTP/.*Cookie.*JSESSIONID',
    'http-weblogic|^HTTP/.*Cookie.*WebLogicSession',
    'http-vnc|^HTTP/.*VNC desktop',
    'http-vnc|^HTTP/.*RealVNC/',
    'ldap|^\x30\x0c\x02\x01\x01\x61',
    'ldap|^\x30\x32\x02\x01',
    'ldap|^\x30\x33\x02\x01',
    'ldap|^\x30\x38\x02\x01',
    'ldap|^\x30\x84',
    'ldap|^\x30\x45',
    'smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
    'msrdp|^\x03\x00\x00\x0b',
    'msrdp|^\x03\x00\x00\x11',
    'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
    'msrdp|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
    'msrdp|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
    'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
    'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
    'msrdp|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
    'msrdp|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
    'msrdp-proxy|^nmproxy: Procotol byte is not 8\n$',
    'msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
    'msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
    'mssql|^\x04\x01\0C..\0\0\xaa\0\0\0/\x0f\xa2\x01\x0e.*',
    'mssql|^\x05\x6e\x00',
    'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
    'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
    'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
    'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
    'mssql|^\x04\x01\0\x25\0\0\x01\0\0\0\x15\0\x06\x01.*',
    'mssql|^\x04\x01\x00\x25\x00\x00\x01.*',
    'telnet|^xff\xfb\x01\xff\xfb\x03\xff\xfb\0\xff\xfd.*',
    'mssql|;MSSQLSERVER;',
    'mysql|^\x19\x00\x00\x00\x0a',
    'mysql|^\x2c\x00\x00\x00\x0a',
    'mysql|hhost \'',
    'mysql|khost \'',
    'mysql|mysqladmin',
    'mysql|whost \'',
    'mysql-blocked|^\(\x00\x00',
    'mysql-secured|this MySQL',
    'mongodb|^.*version.....([\.\d]+)',
    'nagiosd|Sorry, you \(.*are not among the allowed hosts...',
    'nessus|< NTP 1.2 >\x0aUser:',
    'oracle-tns-listener|\(ERROR_STACK=\(ERROR=\(CODE=',
    'oracle-tns-listener|\(ADDRESS=\(PROTOCOL=',
    'oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
    'oracle-https|^220- ora',
    'oracle-rmi|\x00\x00\x00\x76\x49\x6e\x76\x61',
    'oracle-rmi|^\x4e\x00\x09',
    'postgres|Invalid packet length',
    'postgres|^EFATAL',
    'rlogin|login: ',
    'rlogin|rlogind: ',
    'rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
    'rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
    'rpc|\x01\x86\xa0',
    'rpc|\x03\x9b\x65\x42\x00\x00\x00\x01',
    'rpc|^\x80\x00\x00',
    'rsync|^@RSYNCD:.*',
    'smux|^\x41\x01\x02\x00',
    'snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
    'snmp|\x41\x01\x02',
    'socks|^\x05[\x00-\x08]\x00',
    'ssh|^SSH-',
    'ssh|^SSH-.*openssh',
    'ssl|^..\x04\0.\0\x02',
    'ssl|^\x16\x03\x01..\x02...\x03\x01',
    'ssl|^\x16\x03\0..\x02...\x03\0',
    'ssl|SSL.*GET_CLIENT_HELLO',
    'ssl|-ERR .*tls_start_servertls',
    'ssl|^\x16\x03\0\0J\x02\0\0F\x03\0',
    'ssl|^\x16\x03\0..\x02\0\0F\x03\0',
    'ssl|^\x15\x03\0\0\x02\x02\.*',
    'ssl|^\x16\x03\x01..\x02...\x03\x01',
    'ssl|^\x16\x03\0..\x02...\x03\0',
    'sybase|^\x04\x01\x00',
    'telnet|^\xff\xfd',
    'telnet|Telnet is disabled now',
    'telnet|^\xff\xfe',
    'tftp|^\x00[\x03\x05]\x00',
    'http-tomcat|.*Servlet-Engine',
    'uucp|^login: password: ',
    'vnc|^RFB.*',
    'webmin|.*MiniServ',
    'webmin|^0\.0\.0\.0:.*:[0-9]',
    'websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a'
]


def get_server(port):
    SERVER = {
        'FTP': '21',
        'SSH': '22',
        'Telnet': '23',
        'SMTP': '25',
        'DNS': '53',
        'DHCP': '68',
        'HTTP': '80',
        'TFTP': '69',
        'HTTP': '8080',
        'POP3': '995',
        'POP3': '110',
        'NetBIOS': '139',
        'IMAP': '143',
        'HTTPS': '443',
        'SNMP': '161',
        'LDAP': '489',
        'SMB': '445',
        'SMTPS': '465',
        'Linux R RPE': '512',
        'Linux R RLT': '513',
        'Linux R cmd': '514',
        'Rsync': '1873',
        'IMAPS': '993',
        'Proxy': '1080',
        'JavaRMI': '10990',
        'Oracle EMCTL': '1158',
        'Lotus': '1352',
        'MSSQL': '1433',
        'MSSQL Monitor': '1434',
        'Oracle': '1521',
        'PPTP': '1723',
        'cPanel admin panel/CentOS web panel': '2082',
        'CPanel admin panel/CentOS web panel': '2083',
        'Oracle XDB FTP': '2100',
        'Zookeeper': '2181',
        'DA admin panel': '2222',
        'Docker': '2375',
        'Zebra': '2604',
        'Gitea Web': '3000',
        'Squid Proxy': '3128',
        'MySQL/MariaDB': '3306',
        'Kangle admin panel': '3312',
        'RDP': '3389',
        'SVN': '3690',
        'Rundeck': '4440',
        'GlassFish': '4848',
        'SysBase/DB2': '5000',
        'PostgreSql': '5432',
        'PcAnywhere': '5632',
        'VNC': '5900',
        'TeamViewer': '5938',
        'CouchDB': '5984',
        'varnish': '6082',
        'Redis': '6379',
        'Aria2': '6800',
        'Weblogic': '9001',
        'Kloxo admin panel': '7778',
        'Zabbix': '8069',
        'RouterOS/Winbox': '8291',
        'BT/宝塔面板': '8888',
        'WebSphere': '9090',
        'Elasticsearch': '9300',
        'Virtualmin/Webmin': '10000',
        'Zabbix agent': '10050',
        'Zabbix server': '10051',
        'Memcached': '11211',
        'FileZilla Manager': '14147',
        'MongoDB': '27017',
        'MongoDB': '28017',
        'SAP NetWeaver': '50000',
        'Hadoop': '50070',
        'hdfs': '9000',
    }
    for k, v in SERVER.items():
        if v == port:
            return '{}:{}'.format(k, port)
    return 'Unknown:{}'.format(port)


PORTS = [21, 22, 23, 25, 26, 37, 47, 49, 53, 69, 70, 79, 80, 81, 82, 83, 84, 88, 89, 110, 111, 119, 123, 129, 135,
         137, 139, 143, 161, 175, 179, 195, 311, 389, 443, 444, 445, 465, 500, 502, 503, 512, 513, 514, 515, 520,
         523, 530, 548, 554, 563, 587, 593, 623, 626, 631, 636, 660, 666, 749, 751, 771, 789, 873, 888, 901, 902, 990,
         992, 993, 995, 1000, 1010, 1023, 1024, 1025, 1080, 1088, 1099, 1111, 1177, 1200, 1234, 1311, 1325, 1352,
         1400, 1433, 1434, 1471, 1515, 1521, 1599, 1604, 1723, 1741, 1777, 1883, 1900, 1911, 1920, 1962, 1991,
         2000, 2049, 2067, 2081, 2082, 2083, 2086, 2087, 2121, 2123, 2152, 2181, 2222, 2323, 2332, 2333, 2375,
         2376, 2379, 2404, 2433, 2455, 2480, 2601, 2604, 2628, 3000, 3001, 3128, 3260, 3269, 3283, 3299, 3306,
         3307, 3310, 3311, 3312, 3333, 3386, 3388, 3389, 3460, 3478, 3493, 3541, 3542, 3560, 3661, 3689, 3690,
         3702,
         3749, 3794, 3780, 3784, 3790, 4000, 4022, 4040, 4063, 4064, 4070, 4200, 4343, 4369, 4400, 4440, 4443,
         4444,
         4500, 4550, 4567, 4664, 4730, 4782, 4786, 4800, 4840, 4848, 4899, 4911, 4949, 5000, 5001, 5006, 5007,
         5008,
         5009, 5060, 5094, 5222, 5269, 5353, 5357, 5431, 5432, 5433, 5555, 5560, 5577, 5601, 5631, 5632, 5666,
         5672,
         5683, 5800, 5801, 5858, 5900, 5901, 5938, 5984, 5985, 5986, 6000, 6001, 6014, 6082, 6371, 6372, 6373, 6374,
         6379, 6390, 6664,
         6666, 6667, 6881, 6969, 7000, 7001, 7002, 7071, 7080, 7218, 7474, 7547, 7548, 7549, 7657, 7777, 7779,
         7903,
         7905, 8000, 8001, 8008, 8009, 8010, 8060, 8069, 8080, 8081, 8082, 8083, 8086, 8087, 8088, 8089, 8090,
         8098,
         8099, 8112, 8126, 8139, 8140, 8161, 8181, 8191, 8200, 8291, 8307, 8333, 8334, 8443, 8554, 8649, 8688,
         8800, 8834, 8880, 8883, 8888, 8889, 8899, 9000, 9001, 9002, 9009, 9014, 9042, 9043, 9050, 9051, 9080,
         9081, 9090, 9092, 9100, 9151, 9160, 9191, 9200, 9300, 9306, 9418, 9443, 9595, 9600, 9869, 9903, 9943,
         9944, 9981, 9990, 9998, 9999, 10000, 10001, 10050, 10051, 10243, 10554, 11211, 11300, 12345, 13579, 14147,
         16010, 16992, 16993, 17000, 17778, 18081, 18245, 18505, 20000, 20547, 21025, 21379, 21546, 22022, 22222,
         23023, 23389, 23424, 25105, 25565, 27015, 27016, 27017, 27018, 27019, 28015, 28017, 28561, 30000, 30718,
         32400,
         32764, 32768, 32769, 32770, 32771, 33389, 33890, 33899, 37777, 38190, 40001, 40049, 40650, 41706, 42178,
         43382, 44818, 47808, 48899, 49152, 49153, 50000, 50010, 50011, 50015, 50030, 50050, 50060, 50070, 50100,
         51106, 53413, 54138, 55443, 55553, 55554, 62078, 64738, 65535]

PROBE = {
    'GET / HTTP/1.0\r\n\r\n'
}


class ScanPort():
    def __init__(self, ipaddr):
        self.ipaddr = ipaddr
        self.port = []
        self.out = []
        self.num = 0

    def socket_scan(self, hosts):
        global PROBE
        socket.setdefaulttimeout(1)
        ip, port = hosts.split(':')
        try:
            if len(self.port) < 25:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((ip, int(port)))
                if result == 0:
                    self.port.append(port)
                    for i in PROBE:
                        sock.sendall(i.encode())
                        response = sock.recv(256)
                        sock.close()
                        if response:
                            break
                    if response:
                        for pattern in SIGNS:
                            pattern = pattern.split(b'|')
                            if re.search(pattern[-1], response, re.IGNORECASE):
                                proto = '{}:{}'.format(pattern[1].decode(), port)
                                self.out.append(proto)
                                break
            else:
                self.num = 1
        except (socket.timeout, ConnectionResetError):
            pass
        except:
            pass

    def run(self, ip):
        hosts = []
        global PORTS, THREADNUM
        for i in PORTS:
            hosts.append('{}:{}'.format(ip, i))
        try:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=THREADNUM) as executor:
                executor.map(self.socket_scan, hosts)
        except EOFError:
            pass

    def scan(self):
        out = []
        try:
            if (not parse.urlparse(self.ipaddr).path) and (parse.urlparse(self.ipaddr).path != '/'):
                self.ipaddr = self.ipaddr.replace('http://', '').replace('https://', '').rstrip('/')
            else:
                self.ipaddr = self.ipaddr.replace('http://', '').replace('https://', '').rstrip('/')
                self.ipaddr = re.sub('/\w+', '', self.ipaddr)
            if re.search('\d+\.\d+\.\d+\.\d+', self.ipaddr):
                ipaddr = self.ipaddr
            else:
                ipaddr = socket.gethostbyname(self.ipaddr)
            if ':' in ipaddr:
                ipaddr = re.sub(':\d+', '', ipaddr)
            self.run(ipaddr)
        except Exception as e:
            pass
        for i in self.out:
            _, port = i.split(':')
            out.append(port)
        for i in self.port:
            if i not in out:
                self.out.append(get_server(i))
        if self.num == 0:
            return list(set(self.out))
        else:
            return ['Portspoof:0']


if __name__ == "__main__":
    print(ScanPort('127.0.0.1').scan())
