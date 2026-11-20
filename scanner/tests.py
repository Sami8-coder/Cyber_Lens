from django.test import TestCase
from scanner.ssrf import SSRFValidator, SSRFProtectionError

class SSRFValidatorTestCase(TestCase):
    def test_blocks_localhost_and_loopback(self):
        """Test blocking localhost and loopback IPv4/IPv6."""
        with self.assertRaises(SSRFProtectionError):
            SSRFValidator.validate_and_resolve("http://localhost/")

        with self.assertRaises(SSRFProtectionError):
            SSRFValidator.validate_and_resolve("http://127.0.0.1/")

        with self.assertRaises(SSRFProtectionError):
            SSRFValidator.validate_and_resolve("http://127.0.1.1:8080/admin")

    def test_blocks_private_subnets(self):
        """Test blocking RFC 1918 private subnets."""
        with self.assertRaises(SSRFProtectionError):
            SSRFValidator.validate_ip("10.0.0.1")

        with self.assertRaises(SSRFProtectionError):
            SSRFValidator.validate_ip("192.168.1.1")

        with self.assertRaises(SSRFProtectionError):
            SSRFValidator.validate_ip("172.16.0.5")

    def test_blocks_cloud_metadata(self):
        """Test blocking AWS/GCP/Azure link-local metadata address."""
        with self.assertRaises(SSRFProtectionError):
            SSRFValidator.validate_ip("169.254.169.254")

    def test_blocks_non_http_schemes(self):
        """Test rejecting file://, gopher://, ftp:// schemes."""
        with self.assertRaises(SSRFProtectionError):
            SSRFValidator.validate_and_resolve("file:///etc/passwd")

        with self.assertRaises(SSRFProtectionError):
            SSRFValidator.validate_and_resolve("gopher://127.0.0.1/")

    def test_allows_public_domain(self):
        """Test resolving and validating a legitimate public target."""
        url, host, ip = SSRFValidator.validate_and_resolve("https://example.com")
        self.assertEqual(host, "example.com")
        self.assertTrue(url.startswith("https://example.com"))
        self.assertIsNotNone(ip)
