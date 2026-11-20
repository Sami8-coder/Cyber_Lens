import time
import requests
import urllib.parse
from .ssrf import SSRFValidator, SSRFProtectionError

class HTTPScanner:
    """
    Performs passive HTTP and HTTPS inspection:
    - HTTP to HTTPS redirection verification
    - Security headers analysis
    - Information disclosure headers
    - Cookie security flags
    - Safe redirect hops enforcement
    """

    DEFAULT_TIMEOUT = 7.0
    MAX_REDIRECTS = 5

    SECURITY_HEADERS = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Referrer-Policy',
        'Permissions-Policy',
        'Cross-Origin-Opener-Policy',
        'Cross-Origin-Resource-Policy',
        'Cross-Origin-Embedder-Policy',
    ]

    DISCLOSURE_HEADERS = [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'X-Runtime',
        'X-Version',
    ]

    def __init__(self, user_agent: str = None, timeout: float = None):
        self.user_agent = user_agent or 'CyberLens-PostureAuditor/1.0 (+https://cyberlens.local/bot; Security Assessment)'
        self.timeout = timeout or self.DEFAULT_TIMEOUT

    def scan(self, target_url: str, hostname: str) -> dict:
        results = {
            'target_url': target_url,
            'hostname': hostname,
            'final_url': target_url,
            'http_status_code': None,
            'response_time_ms': 0,
            'redirects': [],
            'https_enforced': False,
            'http_to_https_redirect': False,
            'headers': {},
            'raw_headers': {},
            'missing_security_headers': [],
            'present_security_headers': {},
            'disclosure_headers': {},
            'cookies': [],
            'error': None,
        }

        # 1. Test HTTP (port 80) redirection to HTTPS
        results['http_to_https_redirect'] = self._check_http_to_https_redirection(hostname)

        # 2. Perform main request with SSRF validation
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'close',
        })

        start_time = time.time()
        current_url = target_url
        redirect_chain = []

        try:
            for step in range(self.MAX_REDIRECTS + 1):
                # Validate URL before requesting to prevent SSRF via redirection
                SSRFValidator.validate_and_resolve(current_url)

                resp = session.get(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=True,
                    stream=True  # Avoid reading huge payload
                )

                # Capture headers from final or current response
                headers_dict = dict(resp.headers)
                normalized_headers = {k.lower(): v for k, v in headers_dict.items()}

                if resp.is_redirect and 'location' in normalized_headers:
                    next_url = urllib.parse.urljoin(current_url, resp.headers['Location'])
                    redirect_chain.append({
                        'step': step + 1,
                        'from_url': current_url,
                        'to_url': next_url,
                        'status_code': resp.status_code,
                    })
                    current_url = next_url
                else:
                    # Final destination reached
                    results['final_url'] = current_url
                    results['http_status_code'] = resp.status_code
                    results['raw_headers'] = headers_dict
                    results['headers'] = normalized_headers
                    results['response_time_ms'] = int((time.time() - start_time) * 1000)

                    # Check if final destination is HTTPS
                    parsed_final = urllib.parse.urlparse(current_url)
                    results['https_enforced'] = (parsed_final.scheme.lower() == 'https')

                    # Process cookies
                    results['cookies'] = self._extract_cookies(resp)
                    break
            else:
                results['error'] = "Too many redirects encountered (exceeded limit of 5)."

        except requests.exceptions.SSLError as ssl_err:
            results['error'] = f"SSL/TLS Connection Error: {str(ssl_err)}"
            results['response_time_ms'] = int((time.time() - start_time) * 1000)
        except requests.exceptions.Timeout:
            results['error'] = f"Request timed out after {self.timeout} seconds."
            results['response_time_ms'] = int(self.timeout * 1000)
        except SSRFProtectionError as ssrf_err:
            results['error'] = f"SSRF Block: {str(ssrf_err)}"
        except Exception as e:
            results['error'] = f"HTTP Request Failed: {str(e)}"
            results['response_time_ms'] = int((time.time() - start_time) * 1000)

        results['redirects'] = redirect_chain

        # Analyze Security Headers
        self._analyze_headers(results)

        return results

    def _check_http_to_https_redirection(self, hostname: str) -> bool:
        """Passive check: sends an HTTP (port 80) request and checks if it responds with a 301/302 to https."""
        http_url = f"http://{hostname}/"
        try:
            SSRFValidator.validate_and_resolve(http_url)
            resp = requests.get(
                http_url,
                timeout=4.0,
                allow_redirects=False,
                headers={'User-Agent': self.user_agent}
            )
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get('Location', '')
                if location.lower().startswith('https://'):
                    return True
        except Exception:
            pass
        return False

    def _analyze_headers(self, results: dict):
        headers_lower = results.get('headers', {})
        for sec_header in self.SECURITY_HEADERS:
            key_lower = sec_header.lower()
            if key_lower in headers_lower:
                results['present_security_headers'][sec_header] = headers_lower[key_lower]
            else:
                results['missing_security_headers'].append(sec_header)

        for disc_header in self.DISCLOSURE_HEADERS:
            key_lower = disc_header.lower()
            if key_lower in headers_lower:
                results['disclosure_headers'][disc_header] = headers_lower[key_lower]

    def _extract_cookies(self, response) -> list:
        cookie_list = []
        # Extract from response.cookies and raw Set-Cookie headers
        raw_set_cookie = response.headers.get('Set-Cookie', '')
        for c in response.cookies:
            # Inspection of cookie properties
            has_secure = bool(c.secure)
            has_httponly = bool(c.has_nonstandard_attr('HttpOnly') or 'httponly' in str(c._rest).lower())
            samesite = c._rest.get('SameSite', None) or c._rest.get('samesite', None)

            cookie_list.append({
                'name': c.name,
                'value': '***[REDACTED]***', # Never store raw cookie session values for privacy
                'domain': c.domain,
                'path': c.path,
                'secure': has_secure,
                'httponly': has_httponly,
                'samesite': samesite,
                'is_session': c.name.lower() in ('sessionid', 'phpsessid', 'jsessionid', 'token', 'auth', 'connect.sid', 'jwt'),
            })

        # Also fallback parse raw Set-Cookie if requests.cookies missed custom headers
        if not cookie_list and raw_set_cookie:
            for item in raw_set_cookie.split(';'):
                item_str = item.strip()
                if '=' in item_str and not any(k in item_str.lower() for k in ['path=', 'domain=', 'expires=', 'max-age=', 'samesite=']):
                    name = item_str.split('=', 1)[0].strip()
                    cookie_list.append({
                        'name': name,
                        'value': '***[REDACTED]***',
                        'domain': '',
                        'path': '/',
                        'secure': 'secure' in raw_set_cookie.lower(),
                        'httponly': 'httponly' in raw_set_cookie.lower(),
                        'samesite': 'Lax' if 'samesite=lax' in raw_set_cookie.lower() else ('Strict' if 'samesite=strict' in raw_set_cookie.lower() else None),
                        'is_session': False
                    })
                    break

        return cookie_list
