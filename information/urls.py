from django.urls import path
from information import views

urlpatterns = [
    path('portscan/port_scan/', views.port_scan, name="port_scan"),
    path('portscan/', views.portscan, name='portscan'),
    path('delete_port/', views.delete_port, name='delete_port'),
    path('delete_domain/', views.delete_domain, name='delete_domain'),
    path('domainscan/get_subdomain/', views.get_subdomain, name='get_subdomain'),
    path('domainscan/', views.domain_list, name='domainscan'),
    path('subdomains/', views.subdomain_list, name='subdomain'),
    #path('vuln_results', views.vuln_result, name="scan_result"),
    #path('vulnscan/', views.vulnscan, name="vulnscan"),

]