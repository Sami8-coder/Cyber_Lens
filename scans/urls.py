from django.urls import path
from . import views

app_name = 'scans'

urlpatterns = [
    path('new/', views.new_scan_view, name='new_scan'),
    path('history/', views.scan_history_view, name='scan_history'),
    path('compare/', views.scan_compare_view, name='scan_compare'),
    path('api/quick-scan/', views.quick_scan_api, name='quick_scan_api'),
    path('<uuid:scan_uuid>/', views.scan_detail_view, name='scan_detail'),
    path('<uuid:scan_uuid>/rerun/', views.scan_rerun_view, name='scan_rerun'),
    path('<uuid:scan_uuid>/delete/', views.scan_delete_view, name='scan_delete'),
]
