from django.urls import path
from .views import index, download_report, add_ioc, update_mitre_iocs

urlpatterns = [
    path('', index, name='index'),
    path('add_ioc/', add_ioc, name='add_ioc'),
    path('report/', download_report, name='download_report'),
    path('update_mitre_iocs/', update_mitre_iocs, name='update_mitre_iocs'), 
]
