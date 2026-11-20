import json
from django.shortcuts import get_object_or_404, render
from django.http import HttpResponse, JsonResponse, HttpResponseForbidden
from scans.models import Scan
from .pdf_generator import PDFReportGenerator

def download_pdf_view(request, scan_uuid):
    """Generates and serves a downloadable PDF security audit report."""
    scan = get_object_or_404(Scan.objects.prefetch_related('findings'), scan_uuid=scan_uuid)

    if not scan.is_public and scan.user and scan.user != request.user and not request.user.is_staff:
        return HttpResponseForbidden("Access denied.")

    pdf_bytes = PDFReportGenerator.generate_report(scan)

    filename = f"CyberLens_Audit_{scan.target_hostname}_{scan.created_at.strftime('%Y%m%d')}.pdf"
    response = HttpResponse(pdf_bytes, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


def view_report_html(request, scan_uuid):
    """Renders printer-friendly, clean HTML view of the full audit report."""
    scan = get_object_or_404(Scan.objects.prefetch_related('findings'), scan_uuid=scan_uuid)

    if not scan.is_public and scan.user and scan.user != request.user and not request.user.is_staff:
        return HttpResponseForbidden("Access denied.")

    return render(request, 'reports/report_view.html', {
        'scan': scan,
        'findings': scan.findings.all(),
        'severity_counts': scan.get_findings_count_by_severity(),
    })


def export_json_view(request, scan_uuid):
    """Exports structured assessment metadata in machine-readable JSON format."""
    scan = get_object_or_404(Scan.objects.prefetch_related('findings').select_related('raw_data'), scan_uuid=scan_uuid)

    if not scan.is_public and scan.user and scan.user != request.user and not request.user.is_staff:
        return HttpResponseForbidden("Access denied.")

    findings_data = []
    for f in scan.findings.all():
        findings_data.append({
            'title': f.title,
            'category': f.category,
            'severity': f.severity,
            'status': f.status,
            'score_impact': f.score_impact,
            'description': f.description,
            'impact': f.impact,
            'remediation': f.remediation,
            'remediation_code': f.remediation_code,
            'owasp_category': f.owasp_category,
            'cwe_id': f.cwe_id,
            'evidence': f.evidence,
        })

    raw_info = {}
    if hasattr(scan, 'raw_data'):
        raw = scan.raw_data
        raw_info = {
            'headers': raw.headers,
            'cookies': raw.cookies,
            'tls_cert': raw.tls_cert,
            'dns_records': raw.dns_records,
            'http_flow': raw.http_flow,
            'response_meta': raw.response_meta,
        }

    data = {
        'generator': 'CyberLens Security Posture Platform',
        'scan_uuid': str(scan.scan_uuid),
        'target_url': scan.target_url,
        'target_hostname': scan.target_hostname,
        'ip_address': scan.ip_address,
        'status': scan.status,
        'overall_score': scan.overall_score,
        'grade': scan.grade,
        'risk_level': scan.risk_level,
        'category_scores': scan.category_scores,
        'scan_duration_ms': scan.scan_duration_ms,
        'created_at': scan.created_at.isoformat(),
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        'findings': findings_data,
        'raw_data': raw_info,
    }

    filename = f"CyberLens_Data_{scan.target_hostname}.json"
    response = JsonResponse(data, json_dumps_params={'indent': 2})
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
