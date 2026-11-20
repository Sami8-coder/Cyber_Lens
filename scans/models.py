import uuid
from django.db import models
from django.contrib.auth.models import User

class Scan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    GRADE_CHOICES = [
        ('A+', 'A+ (Excellent Posture)'),
        ('A', 'A (Strong Posture)'),
        ('B', 'B (Good / Minor Deficiencies)'),
        ('C', 'C (Moderate Risk)'),
        ('D', 'D (High Risk)'),
        ('F', 'F (Critical Insecurities)'),
    ]

    RISK_LEVEL_CHOICES = [
        ('Secure', 'Secure / Low Risk'),
        ('Low', 'Low Risk'),
        ('Medium', 'Medium Risk'),
        ('High', 'High Risk'),
        ('Critical', 'Critical Risk'),
    ]

    DEPTH_CHOICES = [
        ('quick', 'Quick Scan'),
        ('standard', 'Standard Scan'),
        ('deep', 'Deep Assessment'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='scans')
    target_url = models.URLField(max_length=500, help_text="Original target URL submitted for assessment")
    target_hostname = models.CharField(max_length=255, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    scan_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    error_message = models.TextField(blank=True)
    scan_depth = models.CharField(max_length=20, choices=DEPTH_CHOICES, default='standard')

    # Security scoring (0 - 100)
    overall_score = models.IntegerField(default=0)
    grade = models.CharField(max_length=5, choices=GRADE_CHOICES, default='F')
    risk_level = models.CharField(max_length=20, choices=RISK_LEVEL_CHOICES, default='Critical')

    # Category breakdown (0-100 each): {'ssl': 90, 'headers': 65, 'cookies': 80, 'dns': 70, 'infrastructure': 85}
    category_scores = models.JSONField(default=dict, blank=True)

    # Performance & HTTP Metadata
    scan_duration_ms = models.IntegerField(default=0, help_text="Time taken to scan in milliseconds")
    http_status_code = models.IntegerField(null=True, blank=True)
    final_url = models.URLField(max_length=500, blank=True)
    redirect_count = models.IntegerField(default=0)

    # Privacy / Access
    is_public = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['target_hostname']),
            models.Index(fields=['status']),
            models.Index(fields=['grade']),
        ]

    def __str__(self):
        return f"{self.target_hostname} - Score {self.overall_score} ({self.grade}) [{self.get_status_display()}]"

    @property
    def grade_badge_class(self):
        mapping = {
            'A+': 'badge-grade-aplus',
            'A': 'badge-grade-a',
            'B': 'badge-grade-b',
            'C': 'badge-grade-c',
            'D': 'badge-grade-d',
            'F': 'badge-grade-f',
        }
        return mapping.get(self.grade, 'badge-grade-f')

    @property
    def risk_badge_class(self):
        mapping = {
            'Secure': 'bg-success',
            'Low': 'bg-info',
            'Medium': 'bg-warning text-dark',
            'High': 'bg-danger',
            'Critical': 'bg-dark text-white',
        }
        return mapping.get(self.risk_level, 'bg-secondary')

    def get_findings_count_by_severity(self):
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'pass': 0}
        for finding in self.findings.all():
            sev = finding.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts


class ScanFinding(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
        ('pass', 'Passed Check'),
    ]

    STATUS_CHOICES = [
        ('pass', 'Passed'),
        ('warning', 'Warning'),
        ('fail', 'Failed'),
    ]

    CATEGORY_CHOICES = [
        ('ssl', 'TLS / SSL Security'),
        ('headers', 'HTTP Security Headers'),
        ('cookies', 'Cookie Protection'),
        ('dns', 'DNS & Email Posture (SPF/DMARC/CAA)'),
        ('infrastructure', 'HTTP & Infrastructure Exposure'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='findings')
    title = models.CharField(max_length=255)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    score_impact = models.IntegerField(default=0, help_text="Points deducted or awarded")

    # Explainability fields
    description = models.TextField(help_text="Clear explanation of what was detected")
    impact = models.TextField(help_text="Why this matters, attacker exploitability or privacy risks")
    remediation = models.TextField(help_text="Step-by-step instructions to fix this issue")
    remediation_code = models.TextField(blank=True, help_text="Config snippet e.g. Nginx, Apache, or Django")

    # Technical evidence
    evidence = models.JSONField(default=dict, blank=True, help_text="Observed headers, certificate attributes, or DNS values")
    owasp_category = models.CharField(max_length=100, blank=True, help_text="e.g. A05:2021-Security Misconfiguration")
    cwe_id = models.CharField(max_length=50, blank=True, help_text="e.g. CWE-693: Protection Mechanism Failure")
    order = models.IntegerField(default=0)

    class Meta:
        ordering = ['order', 'status', '-score_impact', 'title']

    def __str__(self):
        return f"[{self.get_severity_display()}] {self.title} ({self.scan.target_hostname})"

    @property
    def severity_badge_class(self):
        mapping = {
            'critical': 'badge-severity-critical',
            'high': 'badge-severity-high',
            'medium': 'badge-severity-medium',
            'low': 'badge-severity-low',
            'info': 'badge-severity-info',
            'pass': 'badge-severity-pass',
        }
        return mapping.get(self.severity.lower(), 'badge-secondary')


class ScanRawData(models.Model):
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name='raw_data')
    headers = models.JSONField(default=dict, blank=True)
    cookies = models.JSONField(default=list, blank=True)
    tls_cert = models.JSONField(default=dict, blank=True)
    dns_records = models.JSONField(default=dict, blank=True)
    http_flow = models.JSONField(default=list, blank=True)
    response_meta = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"Raw Data for Scan {self.scan.id} ({self.scan.target_hostname})"
