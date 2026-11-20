from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('<uuid:scan_uuid>/pdf/', views.download_pdf_view, name='download_pdf'),
    path('<uuid:scan_uuid>/view/', views.view_report_html, name='view_html'),
    path('<uuid:scan_uuid>/json/', views.export_json_view, name='export_json'),
]
