import datetime
import urllib.parse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponseForbidden
from django.db.models import Q
from django.views.decorators.http import require_POST

from .models import Scan, ScanFinding, ScanRawData
from .forms import ScanSubmissionForm
from scanner.engine import ScanningEngine
from scanner.ssrf import SSRFValidator, SSRFProtectionError
from analysis.scoring_engine import ScoringEngine

def run_assessment(target_url: str, user=None, scan_depth: str = 'standard', is_public: bool = False) -> Scan:
    """Internal helper to execute a full scan, evaluate scores, and persist to database."""
    engine = ScanningEngine()
    scoring = ScoringEngine()

    parsed = urllib.parse.urlparse(target_url)
    hostname = (parsed.hostname or '').lower()

    # Create scan record in pending state
    scan = Scan.objects.create(
        user=user if (user and user.is_authenticated) else None,
        target_url=target_url,
        target_hostname=hostname,
        scan_depth=scan_depth,
        status='running',
        is_public=is_public,
    )

    # Execute passive scanner
    raw_results = engine.run_scan(target_url, scan_depth=scan_depth)

    if not raw_results.get('success'):
        scan.status = 'failed'
        scan.error_message = raw_results.get('error', 'Assessment failed to complete.')
        scan.completed_at = datetime.datetime.now(datetime.timezone.utc)
        scan.save()
        return scan

    # Process scoring and explainable findings
    analysis_results = scoring.analyze(raw_results)

    # Save scan metrics
    scan.status = 'completed'
    scan.ip_address = raw_results.get('ip_address')
    scan.target_hostname = raw_results.get('hostname') or hostname
    scan.overall_score = analysis_results['overall_score']
    scan.grade = analysis_results['grade']
    scan.risk_level = analysis_results['risk_level']
    scan.category_scores = analysis_results['category_scores']
    scan.scan_duration_ms = raw_results.get('duration_ms', 0)

    http_data = raw_results.get('http', {})
    scan.http_status_code = http_data.get('http_status_code')
    scan.final_url = http_data.get('final_url', target_url)
    scan.redirect_count = len(http_data.get('redirects', []))
    scan.completed_at = datetime.datetime.now(datetime.timezone.utc)
    scan.save()

    # Persist findings
    for idx, f in enumerate(analysis_results.get('findings', [])):
        ScanFinding.objects.create(
            scan=scan,
            title=f['title'],
            category=f['category'],
            severity=f['severity'],
            status=f['status'],
            score_impact=f['score_impact'],
            description=f['description'],
            impact=f['impact'],
            remediation=f['remediation'],
            remediation_code=f.get('remediation_code', ''),
            evidence=f.get('evidence', {}),
            owasp_category=f.get('owasp_category', ''),
            cwe_id=f.get('cwe_id', ''),
            order=idx,
        )

    # Persist raw technical data
    ScanRawData.objects.create(
        scan=scan,
        headers=http_data.get('raw_headers', {}),
        cookies=http_data.get('cookies', []),
        tls_cert=raw_results.get('tls', {}),
        dns_records=raw_results.get('dns', {}),
        http_flow=http_data.get('redirects', []),
        response_meta={
            'response_time_ms': http_data.get('response_time_ms', 0),
            'https_enforced': http_data.get('https_enforced', False),
            'http_to_https_redirect': http_data.get('http_to_https_redirect', False),
        }
    )

    return scan


def new_scan_view(request):
    """Handles submission of a new security assessment."""
    if request.method == 'POST':
        form = ScanSubmissionForm(request.POST)
        if form.is_valid():
            target_url = form.cleaned_data['target_url']
            scan_depth = form.cleaned_data['scan_depth']
            is_public = form.cleaned_data['is_public']

            scan = run_assessment(
                target_url=target_url,
                user=request.user,
                scan_depth=scan_depth,
                is_public=is_public or not request.user.is_authenticated,
            )

            if scan.status == 'failed':
                messages.error(request, f"Assessment failed: {scan.error_message}")
                return redirect('scans:new_scan')

            messages.success(request, f"Security posture assessment completed for {scan.target_hostname}!")
            return redirect('scans:scan_detail', scan_uuid=scan.scan_uuid)
    else:
        initial_url = request.GET.get('url', '')
        form = ScanSubmissionForm(initial={'target_url': initial_url})

    return render(request, 'scans/new_scan.html', {'form': form})


def scan_detail_view(request, scan_uuid):
    """Renders comprehensive explainable assessment results."""
    scan = get_object_or_404(Scan.objects.prefetch_related('findings').select_related('raw_data'), scan_uuid=scan_uuid)

    # Access control: allow if public, or owned by user, or user is staff
    if not scan.is_public and scan.user and scan.user != request.user and not request.user.is_staff:
        return HttpResponseForbidden("You do not have permission to view this private assessment.")

    findings = scan.findings.all()

    # Findings counts by category
    category_counts = {
        'ssl': findings.filter(category='ssl').count(),
        'headers': findings.filter(category='headers').count(),
        'cookies': findings.filter(category='cookies').count(),
        'dns': findings.filter(category='dns').count(),
        'infrastructure': findings.filter(category='infrastructure').count(),
    }

    # Severity counts
    severity_counts = scan.get_findings_count_by_severity()

    # Pass rate calculation
    total_findings = findings.count()
    pass_count = severity_counts.get('pass', 0)
    pass_rate = int((pass_count / total_findings * 100)) if total_findings > 0 else 0

    return render(request, 'scans/scan_detail.html', {
        'scan': scan,
        'findings': findings,
        'category_counts': category_counts,
        'severity_counts': severity_counts,
        'pass_rate': pass_rate,
        'raw_data': getattr(scan, 'raw_data', None),
    })


def scan_history_view(request):
    """Displays searchable and filterable history of assessments."""
    if request.user.is_authenticated:
        qs = Scan.objects.filter(Q(user=request.user) | Q(is_public=True))
    else:
        qs = Scan.objects.filter(is_public=True)

    query = request.GET.get('q', '').strip()
    grade = request.GET.get('grade', '').strip()
    risk = request.GET.get('risk', '').strip()
    status = request.GET.get('status', '').strip()

    if query:
        qs = qs.filter(Q(target_hostname__icontains=query) | Q(target_url__icontains=query))
    if grade:
        qs = qs.filter(grade=grade)
    if risk:
        qs = qs.filter(risk_level=risk)
    if status:
        qs = qs.filter(status=status)

    paginator = Paginator(qs, 12)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'scans/scan_history.html', {
        'page_obj': page_obj,
        'query': query,
        'selected_grade': grade,
        'selected_risk': risk,
        'selected_status': status,
        'total_scans_count': qs.count(),
    })


@require_POST
def scan_rerun_view(request, scan_uuid):
    """Re-runs an assessment for the same target."""
    old_scan = get_object_or_404(Scan, scan_uuid=scan_uuid)
    new_scan = run_assessment(
        target_url=old_scan.target_url,
        user=request.user if request.user.is_authenticated else old_scan.user,
        scan_depth=old_scan.scan_depth,
        is_public=old_scan.is_public,
    )
    messages.success(request, f"Re-assessment executed for {new_scan.target_hostname}!")
    return redirect('scans:scan_detail', scan_uuid=new_scan.scan_uuid)


@require_POST
@login_required
def scan_delete_view(request, scan_uuid):
    """Deletes a scan record."""
    scan = get_object_or_404(Scan, scan_uuid=scan_uuid)
    if scan.user and scan.user != request.user and not request.user.is_staff:
        return HttpResponseForbidden("Permission denied.")

    hostname = scan.target_hostname
    scan.delete()
    messages.success(request, f"Assessment for {hostname} was deleted.")
    return redirect('scans:scan_history')


def scan_compare_view(request):
    """Compares two security assessments side-by-side."""
    scan1_id = request.GET.get('scan1')
    scan2_id = request.GET.get('scan2')

    scan1 = None
    scan2 = None

    if scan1_id:
        scan1 = Scan.objects.filter(scan_uuid=scan1_id).first()
    if scan2_id:
        scan2 = Scan.objects.filter(scan_uuid=scan2_id).first()

    # List of available user scans for select dropdowns
    if request.user.is_authenticated:
        available_scans = Scan.objects.filter(Q(user=request.user) | Q(is_public=True)).order_by('-created_at')[:30]
    else:
        available_scans = Scan.objects.filter(is_public=True).order_by('-created_at')[:30]

    comparison_data = {}
    if scan1 and scan2:
        score_diff = scan2.overall_score - scan1.overall_score
        comparison_data = {
            'score_diff': score_diff,
            'score_trend': 'improved' if score_diff > 0 else ('degraded' if score_diff < 0 else 'unchanged'),
            'categories': [
                {
                    'name': 'TLS / SSL Cryptography',
                    'score1': scan1.category_scores.get('ssl', 0),
                    'score2': scan2.category_scores.get('ssl', 0),
                    'diff': scan2.category_scores.get('ssl', 0) - scan1.category_scores.get('ssl', 0),
                },
                {
                    'name': 'HTTP Security Headers',
                    'score1': scan1.category_scores.get('headers', 0),
                    'score2': scan2.category_scores.get('headers', 0),
                    'diff': scan2.category_scores.get('headers', 0) - scan1.category_scores.get('headers', 0),
                },
                {
                    'name': 'Cookie Protection',
                    'score1': scan1.category_scores.get('cookies', 0),
                    'score2': scan2.category_scores.get('cookies', 0),
                    'diff': scan2.category_scores.get('cookies', 0) - scan1.category_scores.get('cookies', 0),
                },
                {
                    'name': 'DNS & Email Posture',
                    'score1': scan1.category_scores.get('dns', 0),
                    'score2': scan2.category_scores.get('dns', 0),
                    'diff': scan2.category_scores.get('dns', 0) - scan1.category_scores.get('dns', 0),
                },
                {
                    'name': 'Infrastructure Exposure',
                    'score1': scan1.category_scores.get('infrastructure', 0),
                    'score2': scan2.category_scores.get('infrastructure', 0),
                    'diff': scan2.category_scores.get('infrastructure', 0) - scan1.category_scores.get('infrastructure', 0),
                },
            ]
        }

    return render(request, 'scans/scan_compare.html', {
        'scan1': scan1,
        'scan2': scan2,
        'available_scans': available_scans,
        'comparison': comparison_data,
    })


@require_POST
def quick_scan_api(request):
    """API endpoint for quick asynchronous or instant scan submissions."""
    url = request.POST.get('url', '').strip()
    if not url:
        return JsonResponse({'status': 'error', 'message': 'Target URL is required.'}, status=400)

    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'https://' + url

    try:
        SSRFValidator.validate_and_resolve(url)
    except SSRFProtectionError as e:
        return JsonResponse({'status': 'error', 'message': f"SSRF Block: {str(e)}"}, status=400)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f"Validation Error: {str(e)}"}, status=400)

    scan = run_assessment(
        target_url=url,
        user=request.user,
        scan_depth='standard',
        is_public=True
    )

    if scan.status == 'failed':
        return JsonResponse({'status': 'error', 'message': scan.error_message}, status=500)

    return JsonResponse({
        'status': 'success',
        'scan_uuid': str(scan.scan_uuid),
        'target_hostname': scan.target_hostname,
        'overall_score': scan.overall_score,
        'grade': scan.grade,
        'risk_level': scan.risk_level,
        'detail_url': f"/scans/{scan.scan_uuid}/",
    })
