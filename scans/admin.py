from django.contrib import admin
from .models import Scan, ScanFinding, ScanRawData

class ScanFindingInline(admin.TabularInline):
    model = ScanFinding
    extra = 0
    fields = ('title', 'category', 'severity', 'status', 'score_impact')
    readonly_fields = ('title', 'category', 'severity', 'status', 'score_impact')
    show_change_link = True

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('target_hostname', 'overall_score', 'grade', 'risk_level', 'status', 'user', 'created_at')
    list_filter = ('status', 'grade', 'risk_level', 'scan_depth', 'created_at')
    search_fields = ('target_hostname', 'target_url', 'user__username')
    readonly_fields = ('scan_uuid', 'created_at', 'completed_at')
    inlines = [ScanFindingInline]

@admin.register(ScanFinding)
class ScanFindingAdmin(admin.ModelAdmin):
    list_display = ('title', 'scan', 'category', 'severity', 'status', 'score_impact')
    list_filter = ('category', 'severity', 'status')
    search_fields = ('title', 'description', 'scan__target_hostname')

@admin.register(ScanRawData)
class ScanRawDataAdmin(admin.ModelAdmin):
    list_display = ('scan', )
