from django.test import TestCase
from analysis.scoring_engine import ScoringEngine

class ScoringEngineTestCase(TestCase):
    def setUp(self):
        self.scoring = ScoringEngine()

    def test_ideal_security_posture_scores_a_plus(self):
        """Test scoring engine with optimal security headers and certificates."""
        mock_raw_data = {
            'http': {
                'headers': {
                    'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
                    'content-security-policy': "default-src 'self'",
                    'x-frame-options': 'DENY',
                    'x-content-type-options': 'nosniff',
                    'referrer-policy': 'strict-origin-when-cross-origin',
                    'permissions-policy': 'camera=(), microphone=()',
                    'cross-origin-opener-policy': 'same-origin',
                    'cross-origin-resource-policy': 'same-origin',
                },
                'present_security_headers': {
                    'Strict-Transport-Security': 'max-age=31536000',
                    'Content-Security-Policy': "default-src 'self'",
                },
                'cookies': [
                    {'name': 'sessionid', 'secure': True, 'httponly': True, 'samesite': 'Lax'},
                ],
                'http_to_https_redirect': True,
                'disclosure_headers': {},
            },
            'tls': {
                'has_tls': True,
                'is_valid': True,
                'is_expired': False,
                'is_self_signed': False,
                'days_remaining': 180,
                'protocol_version': 'TLSv1.3',
                'signature_algorithm': 'sha256WithRSAEncryption',
                'issuer': {'commonName': "Let's Encrypt Authority"},
            },
            'dns': {
                'spf_valid': True,
                'spf_record': 'v=spf1 include:_spf.google.com ~all',
                'dmarc_valid': True,
                'dmarc_policy': 'reject',
                'dmarc_record': 'v=DMARC1; p=reject',
                'has_caa': True,
                'has_dnssec': True,
            }
        }

        result = self.scoring.analyze(mock_raw_data)
        self.assertGreaterEqual(result['overall_score'], 90)
        self.assertEqual(result['grade'], 'A+')
        self.assertEqual(result['risk_level'], 'Secure')
        self.assertGreater(len(result['findings']), 0)

    def test_insecure_host_scores_f(self):
        """Test scoring engine with missing headers, expired cert, and no SPF."""
        mock_raw_data = {
            'http': {
                'headers': {},
                'present_security_headers': {},
                'cookies': [
                    {'name': 'sessionid', 'secure': False, 'httponly': False, 'samesite': None},
                ],
                'http_to_https_redirect': False,
                'disclosure_headers': {'Server': 'Apache/2.2.8 (Ubuntu)'},
            },
            'tls': {
                'has_tls': False,
                'is_valid': False,
                'is_expired': True,
            },
            'dns': {
                'spf_valid': False,
                'dmarc_valid': False,
                'has_caa': False,
                'has_dnssec': False,
            }
        }

        result = self.scoring.analyze(mock_raw_data)
        self.assertLessEqual(result['overall_score'], 25)
        self.assertEqual(result['grade'], 'F')
        self.assertEqual(result['risk_level'], 'Critical')
