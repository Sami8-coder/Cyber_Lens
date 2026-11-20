from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Avg, Count, Q
from scans.models import Scan, ScanFinding

@login_required
def index_view(request):
    user = request.user

    # Fetch scans for this user (or public if fresh user)
    user_scans = Scan.objects.filter(user=user)
    total_scans = user_scans.count()

    # If new user has zero scans yet, also show public sample scans so the dashboard isn't blank
    display_scans = user_scans if total_scans > 0 else Scan.objects.filter(is_public=True)
    stats_qs = display_scans.filter(status='completed')

    # Core Metrics
    avg_score_data = stats_qs.aggregate(Avg('overall_score'))
    avg_score = int(round(avg_score_data['overall_score__avg'] or 0))

    critical_risk_count = stats_qs.filter(Q(risk_level='Critical') | Q(risk_level='High')).count()
    secure_count = stats_qs.filter(Q(grade='A+') | Q(grade='A')).count()

    # Grade distribution counts for chart
    grades_counts = {
        'A+': stats_qs.filter(grade='A+').count(),
        'A': stats_qs.filter(grade='A').count(),
        'B': stats_qs.filter(grade='B').count(),
        'C': stats_qs.filter(grade='C').count(),
        'D': stats_qs.filter(grade='D').count(),
        'F': stats_qs.filter(grade='F').count(),
    }

    # Category averages
    cat_averages = {'ssl': 0, 'headers': 0, 'cookies': 0, 'dns': 0, 'infrastructure': 0}
    if stats_qs.exists():
        totals = {'ssl': 0, 'headers': 0, 'cookies': 0, 'dns': 0, 'infrastructure': 0}
        count = 0
        for s in stats_qs:
            scores = s.category_scores or {}
            for k in totals:
                totals[k] += scores.get(k, 0)
            count += 1
        if count > 0:
            for k in totals:
                cat_averages[k] = int(round(totals[k] / count))

    # Top Common Security Vulnerabilities
    top_findings = (
        ScanFinding.objects.filter(scan__in=stats_qs, status='fail')
        .values('title', 'category', 'severity')
        .annotate(occurrences=Count('id'))
        .order_by('-occurrences')[:5]
    )

    # Recent scans (latest 8)
    recent_scans = display_scans.order_by('-created_at')[:8]

    return render(request, 'dashboard/index.html', {
        'total_scans': total_scans,
        'has_personal_scans': total_scans > 0,
        'avg_score': avg_score,
        'critical_risk_count': critical_risk_count,
        'secure_count': secure_count,
        'grades_counts': grades_counts,
        'cat_averages': cat_averages,
        'top_findings': top_findings,
        'recent_scans': recent_scans,
    })
