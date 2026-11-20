from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from scans.models import Scan, ScanFinding
from reports.pdf_generator import PDFReportGenerator

class ReportsTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='reportuser', password='Password123!')
        self.scan = Scan.objects.create(
            user=self.user,
            target_url='https://cyberlens.local',
            target_hostname='cyberlens.local',
            ip_address='198.51.100.1',
            overall_score=92,
            grade='A+',
            risk_level='Secure',
            category_scores={'ssl': 95, 'headers': 90, 'cookies': 90, 'dns': 90, 'infrastructure': 95},
            status='completed',
            is_public=True
        )

        ScanFinding.objects.create(
            scan=self.scan,
            title='TLS 1.3 Negotiated',
            category='ssl',
            severity='pass',
            status='pass',
            score_impact=0,
            description='Modern protocol version in use.',
            impact='Guarantees forward secrecy and strong encryption.',
            remediation='Continue enforcing TLS 1.3.',
            remediation_code='ssl_protocols TLSv1.3;'
        )

    def test_pdf_report_generator_binary(self):
        """Test that PDFReportGenerator produces valid PDF bytes."""
        pdf_data = PDFReportGenerator.generate_report(self.scan)
        self.assertIsInstance(pdf_data, bytes)
        self.assertTrue(pdf_data.startswith(b'%PDF-'))
        self.assertGreater(len(pdf_data), 1000)

    def test_download_pdf_view_response(self):
        """Test downloading PDF report via HTTP endpoint."""
        response = self.client.get(reverse('reports:download_pdf', kwargs={'scan_uuid': self.scan.scan_uuid}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('attachment', response['Content-Disposition'])

    def test_export_json_view(self):
        """Test exporting structured scan data as JSON."""
        response = self.client.get(reverse('reports:export_json', kwargs={'scan_uuid': self.scan.scan_uuid}))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['target_hostname'], 'cyberlens.local')
        self.assertEqual(data['overall_score'], 92)
        self.assertEqual(data['grade'], 'A+')
        self.assertEqual(len(data['findings']), 1)
