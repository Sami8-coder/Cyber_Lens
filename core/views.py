from django.shortcuts import render
from scans.models import Scan

def home_view(request):
    """Modern SaaS landing page for CyberLens with live scan showcase."""
    recent_public_scans = Scan.objects.filter(is_public=True, status='completed').order_by('-created_at')[:6]
    return render(request, 'core/home.html', {
        'recent_scans': recent_public_scans,
    })

def about_view(request):
    """About CyberLens: Architecture, Academic Context, Security Principles."""
    return render(request, 'core/about.html')

def docs_view(request):
    """Technical Documentation: Methodology, Scoring Formula, SSRF Protection, CWE references."""
    return render(request, 'core/docs.html')

def handler404_view(request, exception=None):
    return render(request, 'core/404.html', status=404)

def handler500_view(request):
    return render(request, 'core/500.html', status=500)
