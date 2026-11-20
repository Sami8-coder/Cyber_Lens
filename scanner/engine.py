import time
from .ssrf import SSRFValidator, SSRFProtectionError
from .http_scanner import HTTPScanner
from .tls_scanner import TLSScanner
from .dns_scanner import DNSScanner

class ScanningEngine:
    """
    Coordinates multi-layered passive security assessment:
    - URL validation & SSRF protection
    - HTTP headers & redirection
    - Cookie security flags
    - TLS/SSL handshake & certificate validation
    - DNS records, SPF, DMARC, CAA
    """

    def __init__(self, timeout: float = 7.0):
        self.timeout = timeout
        self.http_scanner = HTTPScanner(timeout=timeout)
        self.tls_scanner = TLSScanner(timeout=timeout)
        self.dns_scanner = DNSScanner(timeout=4.0)

    def run_scan(self, input_url: str, scan_depth: str = 'standard') -> dict:
        start_time = time.time()
        output = {
            'input_url': input_url,
            'normalized_url': '',
            'hostname': '',
            'ip_address': '',
            'scan_depth': scan_depth,
            'duration_ms': 0,
            'http': {},
            'tls': {},
            'dns': {},
            'success': False,
            'error': None,
        }

        # Step 1: SSRF Validation and Hostname Resolution
        try:
            normalized_url, hostname, ip_address = SSRFValidator.validate_and_resolve(input_url)
            output['normalized_url'] = normalized_url
            output['hostname'] = hostname
            output['ip_address'] = ip_address
        except SSRFProtectionError as err:
            output['error'] = f"Security Policy Violation: {str(err)}"
            output['duration_ms'] = int((time.time() - start_time) * 1000)
            return output
        except Exception as err:
            output['error'] = f"Validation Error: {str(err)}"
            output['duration_ms'] = int((time.time() - start_time) * 1000)
            return output

        # Step 2: HTTP / Security Headers / Cookies
        try:
            http_data = self.http_scanner.scan(normalized_url, hostname)
            output['http'] = http_data
        except Exception as err:
            output['http'] = {'error': str(err), 'headers': {}, 'cookies': []}

        # Step 3: TLS / SSL Certificate Inspection
        try:
            tls_data = self.tls_scanner.scan(hostname, port=443)
            output['tls'] = tls_data
        except Exception as err:
            output['tls'] = {'error': str(err), 'has_tls': False}

        # Step 4: DNS / SPF / DMARC / CAA Inspection
        try:
            dns_data = self.dns_scanner.scan(hostname)
            output['dns'] = dns_data
        except Exception as err:
            output['dns'] = {'error': str(err), 'a_records': []}

        output['duration_ms'] = int((time.time() - start_time) * 1000)
        output['success'] = True
        return output
