from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('add_ioc/', views.add_ioc, name='add_ioc'),
    path('download_report/', views.download_report, name='download_report'),
    path('update_mitre_iocs/', views.update_mitre_iocs, name='update_mitre_iocs'),
    path('update_threat_intel/', views.update_threat_intel, name='update_threat_intel'),
    # test data insertion
    path('insert_test_data/', views.insert_test_data, name='insert_test_data'),
]