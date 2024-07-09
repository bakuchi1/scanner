from django.urls import path, include
from django.urls import path
from . import views

urlpatterns = [
    path('add_scan/', views.add_scan, name="add_scan"),
    #path('vuln_results', views.vuln_result, name="scan_result"),
    path('vulnscan/', views.vulnscan, name="vulnscan"),
    path('get_vuln_rank', views.get_vuln_rank, name="get_vuln_rank"),
    path('get_vuln_value', views.get_vuln_value, name="get_vuln_value"),

]
target_ids = views.get_target_id()
vuln_ids = views.get_vuln_id()
for target_id in target_ids:
    urlpatterns.append(path('vulnscan/vuln_result/<target_id>/', views.vuln_result, name = 'vuln_result/'+target_id))
for vuln_id in vuln_ids:
    urlpatterns.append(path('vuln_detail/<vuln_id>/', views.vuln_detail, name='vuln_detail/' + vuln_id))
