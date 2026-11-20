from datetime import datetime, timezone
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from scans.models import Scan, ScanFinding, ScanRawData
from analysis.knowledge_base import KNOWLEDGE_BASE

class Command(BaseCommand):
    help = 'Seeds sample demonstration users and realistic posture assessment records.'

    def handle(self, *args, **options):
        self.stdout.write("Seeding CyberLens demonstration users and assessments...")

        # 1. Create or get admin user
        admin_user, created = User.objects.get_or_create(
            username='admin',
            defaults={
                'email': 'admin@cyberlens.local',
                'first_name': 'Chief',
                'last_name': 'Auditor',
                'is_staff': True,
                'is_superuser': True,
            }
        )
        if created:
            admin_user.set_password('AdminPass123!')
            admin_user.save()
            admin_user.profile.organization = 'CyberLens Security Labs'
            admin_user.profile.job_title = 'Chief Information Security Officer'
            admin_user.profile.save()
            self.stdout.write(self.style.SUCCESS("Created demo admin: admin / AdminPass123!"))
        else:
            self.stdout.write("Admin user already exists.")

        # 2. Create demo analyst
        analyst_user, created = User.objects.get_or_create(
            username='analyst',
            defaults={
                'email': 'analyst@cyberlens.local',
                'first_name': 'Alex',
                'last_name': 'Mercer',
                'is_staff': False,
            }
        )
        if created:
            analyst_user.set_password('AnalystPass123!')
            analyst_user.save()
            analyst_user.profile.organization = 'CSE University Cybersecurity Club'
            analyst_user.profile.job_title = 'Security Analyst'
            analyst_user.profile.save()
            self.stdout.write(self.style.SUCCESS("Created demo analyst: analyst / AnalystPass123!"))

        # 3. Create Sample Posture Audits
        samples = [
            {
                'url': 'https://cloudflare.com',
                'host': 'cloudflare.com',
                'ip': '104.16.132.229',
                'score': 95,
                'grade': 'A+',
                'risk': 'Secure',
                'cat_scores': {'ssl': 100, 'headers': 94, 'cookies': 95, 'dns': 92, 'infrastructure': 95},
                'duration': 420,
                'findings': [
                    ('HSTS Properly Configured', 'headers', 'pass', 'pass', 0, 'HSTS',
                     'Strict-Transport-Security enforced with max-age >= 1 year.',
                     'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;'),
                    ('Valid TLS 1.3 Encryption', 'ssl', 'pass', 'pass', 0, 'TLS_VERSION',
                     'Negotiated TLSv1.3 with AES-256-GCM cipher suite.',
                     'ssl_protocols TLSv1.3;'),
                    ('DMARC Enforcement Active (Policy: reject)', 'dns', 'pass', 'pass', 0, 'DMARC_RECORD',
                     'Strict p=reject policy active at _dmarc.cloudflare.com.',
                     'v=DMARC1; p=reject; rua=mailto:dmarc@cloudflare.com'),
                    ('Cookies Enforce Secure and SameSite', 'cookies', 'pass', 'pass', 0, 'COOKIE_SECURITY',
                     'All session cookies enforce Secure and SameSite attributes.',
                     'SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_SAMESITE = "Lax"'),
                ]
            },
            {
                'url': 'https://github.com',
                'host': 'github.com',
                'ip': '140.82.121.4',
                'score': 88,
                'grade': 'A',
                'risk': 'Low',
                'cat_scores': {'ssl': 95, 'headers': 88, 'cookies': 85, 'dns': 85, 'infrastructure': 90},
                'duration': 510,
                'findings': [
                    ('HSTS Properly Configured', 'headers', 'pass', 'pass', 0, 'HSTS',
                     'Strict-Transport-Security is enforced.',
                     'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;'),
                    ('Content Security Policy Enforced', 'headers', 'pass', 'pass', 0, 'CSP',
                     'Strict CSP active across resources.',
                     'add_header Content-Security-Policy "default-src \'self\';" always;'),
                    ('Missing CAA DNS Records', 'dns', 'low', 'warning', -10, 'CAA_RECORD',
                     'No CAA records found in DNS.',
                     'github.com. IN CAA 0 issue "digicert.com"'),
                    ('Server Information Disclosed', 'infrastructure', 'medium', 'warning', -15, 'SERVER_DISCLOSURE',
                     'Server header reports GitHub.com proxy banner.',
                     'server_tokens off;'),
                ]
            },
            {
                'url': 'https://legacy-portal.example.org',
                'host': 'legacy-portal.example.org',
                'ip': '198.51.100.45',
                'score': 42,
                'grade': 'D',
                'risk': 'High',
                'cat_scores': {'ssl': 60, 'headers': 30, 'cookies': 40, 'dns': 35, 'infrastructure': 45},
                'duration': 830,
                'findings': [
                    ('Missing Strict-Transport-Security (HSTS)', 'headers', 'high', 'fail', -22, 'HSTS',
                     'No HSTS header present on response.',
                     'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains;" always;'),
                    ('Missing Content Security Policy (CSP)', 'headers', 'high', 'fail', -20, 'CSP',
                     'CSP header is absent. Susceptible to XSS injections.',
                     'add_header Content-Security-Policy "default-src \'self\';" always;'),
                    ('Cookies Missing Secure Flag', 'cookies', 'high', 'fail', -30, 'COOKIE_SECURITY',
                     'Session cookies sent without Secure flag.',
                     'SESSION_COOKIE_SECURE = True'),
                    ('Missing DMARC Record', 'dns', 'high', 'fail', -35, 'DMARC_RECORD',
                     'Domain lacks DMARC email spoofing protection.',
                     '_dmarc.legacy-portal.example.org. IN TXT "v=DMARC1; p=quarantine;"'),
                    ('Server Version Banner Exposed', 'infrastructure', 'medium', 'warning', -20, 'SERVER_DISCLOSURE',
                     'Server reveals: Apache/2.4.29 (Ubuntu) PHP/7.2.24',
                     'ServerTokens Prod\nServerSignature Off'),
                ]
            }
        ]

        for s in samples:
            scan, _ = Scan.objects.get_or_create(
                target_hostname=s['host'],
                defaults={
                    'user': admin_user,
                    'target_url': s['url'],
                    'ip_address': s['ip'],
                    'overall_score': s['score'],
                    'grade': s['grade'],
                    'risk_level': s['risk'],
                    'category_scores': s['cat_scores'],
                    'status': 'completed',
                    'is_public': True,
                    'scan_duration_ms': s['duration'],
                    'http_status_code': 200,
                    'final_url': s['url'],
                    'completed_at': datetime.now(timezone.utc),
                }
            )

            # Add sample findings if newly created
            if scan.findings.count() == 0:
                for idx, f in enumerate(s['findings']):
                    kb = KNOWLEDGE_BASE.get(f[5], {})
                    ScanFinding.objects.create(
                        scan=scan,
                        title=f[0],
                        category=f[1],
                        severity=f[2],
                        status=f[3],
                        score_impact=f[4],
                        description=f[6],
                        impact=kb.get('impact', 'Potential security vulnerability.'),
                        remediation=kb.get('remediation', 'Implement recommended defense.'),
                        remediation_code=f[7],
                        owasp_category=kb.get('owasp', 'A05:2021-Security Misconfiguration'),
                        cwe_id=kb.get('cwe', 'CWE-693'),
                        order=idx
                    )

                ScanRawData.objects.get_or_create(
                    scan=scan,
                    defaults={
                        'headers': {'server': 'nginx', 'date': 'Thu, 20 Nov 2026 12:00:00 GMT'},
                        'cookies': [{'name': 'sessionid', 'secure': True, 'httponly': True, 'samesite': 'Lax'}],
                        'tls_cert': {'has_tls': True, 'protocol_version': 'TLSv1.3', 'days_remaining': 120, 'signature_algorithm': 'sha256WithRSAEncryption'},
                        'dns_records': {'a_records': [s['ip']], 'spf_valid': True, 'dmarc_valid': True},
                        'http_flow': [],
                        'response_meta': {'response_time_ms': 120, 'https_enforced': True, 'http_to_https_redirect': True}
                    }
                )

        self.stdout.write(self.style.SUCCESS("Successfully seeded demonstration data!"))
