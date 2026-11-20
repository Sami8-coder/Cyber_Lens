import uuid
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from .models import Scan, ScanFinding, ScanRawData

class ScansTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='auditor1', password='Password123!')
        self.scan1 = Scan.objects.create(
            user=self.user,
            target_url='https://example.com',
            target_hostname='example.com',
            ip_address='93.184.216.34',
            overall_score=85,
            grade='A',
            risk_level='Low',
            category_scores={'ssl': 90, 'headers': 80, 'cookies': 85, 'dns': 80, 'infrastructure': 90},
            status='completed',
            is_public=True
        )
        self.scan2 = Scan.objects.create(
            user=self.user,
            target_url='https://example.com',
            target_hostname='example.com',
            ip_address='93.184.216.34',
            overall_score=95,
            grade='A+',
            risk_level='Secure',
            category_scores={'ssl': 100, 'headers': 95, 'cookies': 90, 'dns': 90, 'infrastructure': 100},
            status='completed',
            is_public=True
        )

        ScanFinding.objects.create(
            scan=self.scan1,
            title='Strict-Transport-Security Configured',
            category='headers',
            severity='pass',
            status='pass',
            score_impact=0,
            description='HSTS is properly enabled.',
            impact='Mitigates SSL stripping.',
            remediation='Maintain 1-year max age.'
        )

        ScanRawData.objects.create(
            scan=self.scan1,
            headers={'server': 'ECS'},
            cookies=[],
            tls_cert={'has_tls': True},
            dns_records={'a_records': ['93.184.216.34']},
        )

    def test_scan_detail_view(self):
        """Test retrieving scan detail page."""
        response = self.client.get(reverse('scans:scan_detail', kwargs={'scan_uuid': self.scan1.scan_uuid}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'example.com')
        self.assertContains(response, '85')
        self.assertContains(response, 'Strict-Transport-Security Configured')

    def test_scan_history_view_filtering(self):
        """Test filtering scan history by grade."""
        response = self.client.get(reverse('scans:scan_history') + '?grade=A')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'example.com')

    def test_scan_compare_view(self):
        """Test comparison between two assessments."""
        url = reverse('scans:scan_compare') + f"?scan1={self.scan1.scan_uuid}&scan2={self.scan2.scan_uuid}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Posture Improved by +10 points')

    def test_quick_scan_api_ssrf_protection(self):
        """Test that API endpoint enforces SSRF blocks."""
        response = self.client.post(reverse('scans:quick_scan_api'), {'url': 'http://127.0.0.1:8000'})
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['status'], 'error')
        self.assertIn('SSRF Block', data['message'])
