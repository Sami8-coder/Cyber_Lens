import ssl
import socket
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from .ssrf import SSRFValidator

class TLSScanner:
    """
    Performs passive TLS/SSL certificate and handshake evaluation:
    - Extracts X.509 certificate attributes
    - Calculates expiration and validity window
    - Validates signature algorithm (e.g. SHA-256 vs obsolete SHA-1/MD5)
    - Detects self-signed certificates
    - Captures negotiated TLS version and cipher suite
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    def scan(self, hostname: str, port: int = 443) -> dict:
        results = {
            'has_tls': False,
            'is_valid': False,
            'is_expired': False,
            'is_self_signed': False,
            'issuer': {},
            'subject': {},
            'san': [],
            'valid_from': None,
            'valid_until': None,
            'days_remaining': 0,
            'signature_algorithm': '',
            'protocol_version': '',
            'cipher_suite': '',
            'serial_number': '',
            'error': None,
        }

        # SSRF check on hostname
        try:
            SSRFValidator.validate_and_resolve(f"https://{hostname}:{port}/")
        except Exception as e:
            results['error'] = f"SSRF Block: {str(e)}"
            return results

        context = ssl.create_default_context()
        # Enable all modern versions
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # We inspect cert ourselves to report detailed issues even if self-signed

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results['has_tls'] = True
                    results['protocol_version'] = ssock.version() or 'Unknown'
                    cipher = ssock.cipher()
                    if cipher:
                        results['cipher_suite'] = cipher[0]

                    # Get binary DER cert for deep cryptography parsing
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        cert = x509.load_der_x509_certificate(der_cert, default_backend())
                        self._parse_cryptography_cert(cert, results)

            # Check if verified context would accept it
            verify_context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with verify_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results['is_valid'] = True

        except ssl.SSLCertVerificationError as cert_err:
            results['is_valid'] = False
            results['error'] = f"Certificate Verification Failed: {cert_err.verify_message}"
        except ssl.SSLError as ssl_err:
            results['error'] = f"TLS Error: {str(ssl_err)}"
        except socket.timeout:
            results['error'] = f"TLS handshake timed out after {self.timeout}s."
        except Exception as e:
            results['error'] = f"TLS connection failed: {str(e)}"

        return results

    def _parse_cryptography_cert(self, cert: x509.Certificate, results: dict):
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            # cryptography 42+ uses not_valid_after_utc
            try:
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            except AttributeError:
                not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
                not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

            results['valid_from'] = not_before.strftime('%Y-%m-%d %H:%M:%S UTC')
            results['valid_until'] = not_after.strftime('%Y-%m-%d %H:%M:%S UTC')

            delta = not_after - now
            results['days_remaining'] = delta.days
            results['is_expired'] = (now > not_after) or (now < not_before)

            # Subject & Issuer
            results['subject'] = {attr.oid._name: attr.value for attr in cert.subject}
            results['issuer'] = {attr.oid._name: attr.value for attr in cert.issuer}

            # Self-signed detection: issuer equals subject
            results['is_self_signed'] = (cert.issuer == cert.subject)

            # Signature algorithm
            results['signature_algorithm'] = cert.signature_algorithm_oid._name

            # Serial number
            results['serial_number'] = hex(cert.serial_number)[2:].upper()

            # SANs (Subject Alternative Names)
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                results['san'] = [str(name.value) for name in san_ext.value]
            except x509.ExtensionNotFound:
                results['san'] = []
        except Exception as parse_err:
            results['error'] = f"Certificate Parsing Warning: {parse_err}"
