from .knowledge_base import KNOWLEDGE_BASE

class ScoringEngine:
    """
    Evaluates raw scan outputs, computes transparent security scores (0-100),
    assigns letter grades (A+ to F), and produces explainable findings with
    OWASP/CWE references and remediation snippets.
    """

    # Category Weights (Total = 100%)
    WEIGHTS = {
        'headers': 0.35,
        'ssl': 0.25,
        'cookies': 0.15,
        'dns': 0.15,
        'infrastructure': 0.10,
    }

    def analyze(self, raw_data: dict) -> dict:
        findings = []

        # Analyze each category
        headers_score, headers_findings = self._evaluate_headers(raw_data.get('http', {}))
        ssl_score, ssl_findings = self._evaluate_ssl(raw_data.get('tls', {}), raw_data.get('http', {}))
        cookies_score, cookies_findings = self._evaluate_cookies(raw_data.get('http', {}).get('cookies', []))
        dns_score, dns_findings = self._evaluate_dns(raw_data.get('dns', {}))
        infra_score, infra_findings = self._evaluate_infrastructure(raw_data.get('http', {}))

        findings.extend(headers_findings)
        findings.extend(ssl_findings)
        findings.extend(cookies_findings)
        findings.extend(dns_findings)
        findings.extend(infra_findings)

        category_scores = {
            'headers': int(round(headers_score)),
            'ssl': int(round(ssl_score)),
            'cookies': int(round(cookies_score)),
            'dns': int(round(dns_score)),
            'infrastructure': int(round(infra_score)),
        }

        # Calculate composite weighted overall score
        overall_score = int(round(
            category_scores['headers'] * self.WEIGHTS['headers'] +
            category_scores['ssl'] * self.WEIGHTS['ssl'] +
            category_scores['cookies'] * self.WEIGHTS['cookies'] +
            category_scores['dns'] * self.WEIGHTS['dns'] +
            category_scores['infrastructure'] * self.WEIGHTS['infrastructure']
        ))

        # Clamp between 0 and 100
        overall_score = max(0, min(100, overall_score))

        # Determine letter grade
        if overall_score >= 90:
            grade = 'A+'
            risk_level = 'Secure'
        elif overall_score >= 80:
            grade = 'A'
            risk_level = 'Low'
        elif overall_score >= 70:
            grade = 'B'
            risk_level = 'Low'
        elif overall_score >= 50:
            grade = 'C'
            risk_level = 'Medium'
        elif overall_score >= 30:
            grade = 'D'
            risk_level = 'High'
        else:
            grade = 'F'
            risk_level = 'Critical'

        return {
            'overall_score': overall_score,
            'grade': grade,
            'risk_level': risk_level,
            'category_scores': category_scores,
            'findings': findings,
        }

    def _evaluate_headers(self, http_data: dict) -> tuple[float, list]:
        score = 100.0
        findings = []
        headers = http_data.get('headers', {})
        present = http_data.get('present_security_headers', {})

        # 1. HSTS (High impact: -20 if missing, -5 if max-age < 1 yr)
        if 'strict-transport-security' in headers:
            hsts_val = headers['strict-transport-security']
            kb = KNOWLEDGE_BASE['HSTS']
            has_sub = 'includesubdomains' in hsts_val.lower()
            has_preload = 'preload' in hsts_val.lower()

            # Parse max-age
            max_age = 0
            for part in hsts_val.split(';'):
                part = part.strip().lower()
                if part.startswith('max-age='):
                    try:
                        max_age = int(part.split('=')[1])
                    except ValueError:
                        pass

            if max_age >= 31536000:
                findings.append(self._make_finding(
                    title="HSTS Properly Configured",
                    category="headers",
                    severity="pass",
                    status="pass",
                    score_impact=0,
                    kb_key="HSTS",
                    description=f"Strict-Transport-Security is enforced with a robust max-age ({max_age}s / >= 1 year).",
                    evidence={"value": hsts_val, "includeSubDomains": has_sub, "preload": has_preload}
                ))
            else:
                score -= 8
                findings.append(self._make_finding(
                    title="HSTS Max-Age is Too Short",
                    category="headers",
                    severity="medium",
                    status="warning",
                    score_impact=-8,
                    kb_key="HSTS",
                    description=f"HSTS is enabled but max-age is {max_age}s, which is below the recommended 1 year (31536000s).",
                    evidence={"value": hsts_val}
                ))
        else:
            score -= 22
            findings.append(self._make_finding(
                title="Missing Strict-Transport-Security (HSTS)",
                category="headers",
                severity="high",
                status="fail",
                score_impact=-22,
                kb_key="HSTS",
                description="The Strict-Transport-Security header is not present on HTTP responses.",
                evidence={"status": "Header not found"}
            ))

        # 2. CSP (High impact: -22 if missing)
        if 'content-security-policy' in headers:
            csp_val = headers['content-security-policy']
            is_weak = "'unsafe-inline'" in csp_val or "'unsafe-eval'" in csp_val
            if is_weak:
                score -= 6
                findings.append(self._make_finding(
                    title="Content Security Policy Contains Unsafe Directives",
                    category="headers",
                    severity="medium",
                    status="warning",
                    score_impact=-6,
                    kb_key="CSP",
                    description="CSP is present but contains 'unsafe-inline' or 'unsafe-eval', weakening XSS defense.",
                    evidence={"value": csp_val[:200] + ("..." if len(csp_val) > 200 else "")}
                ))
            else:
                findings.append(self._make_finding(
                    title="Content Security Policy Enforced",
                    category="headers",
                    severity="pass",
                    status="pass",
                    score_impact=0,
                    kb_key="CSP",
                    description="Content-Security-Policy is active and restricts unauthorized scripts and frames.",
                    evidence={"value": csp_val[:200] + ("..." if len(csp_val) > 200 else "")}
                ))
        else:
            score -= 20
            findings.append(self._make_finding(
                title="Missing Content Security Policy (CSP)",
                category="headers",
                severity="high",
                status="fail",
                score_impact=-20,
                kb_key="CSP",
                description="No Content-Security-Policy header detected. Browsers will execute any inline or third-party resources.",
                evidence={"status": "Header not found"}
            ))

        # 3. X-Frame-Options (Clickjacking) (-15)
        if 'x-frame-options' in headers:
            xfo_val = headers['x-frame-options'].upper()
            findings.append(self._make_finding(
                title="X-Frame-Options Configured",
                category="headers",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="X_FRAME_OPTIONS",
                description=f"Framing protection active with policy: {xfo_val}.",
                evidence={"value": xfo_val}
            ))
        else:
            score -= 15
            findings.append(self._make_finding(
                title="Missing X-Frame-Options (Clickjacking Risk)",
                category="headers",
                severity="medium",
                status="fail",
                score_impact=-15,
                kb_key="X_FRAME_OPTIONS",
                description="X-Frame-Options header is absent. Site is vulnerable to UI clickjacking attacks.",
                evidence={"status": "Header not found"}
            ))

        # 4. X-Content-Type-Options (nosniff) (-15)
        if headers.get('x-content-type-options', '').lower() == 'nosniff':
            findings.append(self._make_finding(
                title="X-Content-Type-Options Enforced",
                category="headers",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="X_CONTENT_TYPE_OPTIONS",
                description="MIME-sniffing protection enabled with 'nosniff'.",
                evidence={"value": "nosniff"}
            ))
        else:
            score -= 15
            findings.append(self._make_finding(
                title="Missing X-Content-Type-Options",
                category="headers",
                severity="medium",
                status="fail",
                score_impact=-15,
                kb_key="X_CONTENT_TYPE_OPTIONS",
                description="MIME-sniffing protection is disabled or missing.",
                evidence={"status": "Header missing or invalid"}
            ))

        # 5. Referrer-Policy (-12)
        if 'referrer-policy' in headers:
            findings.append(self._make_finding(
                title="Referrer-Policy Configured",
                category="headers",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="REFERRER_POLICY",
                description=f"Referrer-Policy defined: {headers['referrer-policy']}.",
                evidence={"value": headers['referrer-policy']}
            ))
        else:
            score -= 12
            findings.append(self._make_finding(
                title="Missing Referrer-Policy Header",
                category="headers",
                severity="low",
                status="warning",
                score_impact=-12,
                kb_key="REFERRER_POLICY",
                description="Referrer-Policy header is missing; sensitive URLs may leak in HTTP Referer headers.",
                evidence={"status": "Header not found"}
            ))

        # 6. Permissions-Policy (-8)
        if 'permissions-policy' in headers or 'feature-policy' in headers:
            findings.append(self._make_finding(
                title="Permissions-Policy Configured",
                category="headers",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="PERMISSIONS_POLICY",
                description="Browser hardware and sensor capabilities are restricted.",
                evidence={"value": headers.get('permissions-policy', headers.get('feature-policy', ''))}
            ))
        else:
            score -= 8
            findings.append(self._make_finding(
                title="Missing Permissions-Policy",
                category="headers",
                severity="low",
                status="warning",
                score_impact=-8,
                kb_key="PERMISSIONS_POLICY",
                description="No Permissions-Policy header found. Web platform APIs are not explicitly restricted.",
                evidence={"status": "Header not found"}
            ))

        # 7. COOP / CORP (-8)
        if 'cross-origin-opener-policy' in headers or 'cross-origin-resource-policy' in headers:
            findings.append(self._make_finding(
                title="Cross-Origin Isolation Headers Present",
                category="headers",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="COOP_CORP",
                description="Cross-Origin Opener / Resource policies help isolate the window browsing context.",
                evidence={"coop": headers.get('cross-origin-opener-policy', 'absent'), "corp": headers.get('cross-origin-resource-policy', 'absent')}
            ))
        else:
            score -= 8
            findings.append(self._make_finding(
                title="Missing Cross-Origin Isolation (COOP/CORP)",
                category="headers",
                severity="low",
                status="info",
                score_impact=-8,
                kb_key="COOP_CORP",
                description="COOP and CORP headers are not defined, permitting cross-origin window probing.",
                evidence={"status": "COOP/CORP absent"}
            ))

        return max(0.0, score), findings

    def _evaluate_ssl(self, tls_data: dict, http_data: dict) -> tuple[float, list]:
        score = 100.0
        findings = []

        if not tls_data.get('has_tls', False):
            # No TLS at all
            score = 0.0
            findings.append(self._make_finding(
                title="HTTPS / TLS Not Supported on Host",
                category="ssl",
                severity="critical",
                status="fail",
                score_impact=-100,
                kb_key="TLS_CERTIFICATE",
                description="The target server does not establish a TLS handshake on port 443.",
                evidence={"error": tls_data.get('error', 'Connection refused')}
            ))
            return score, findings

        # Certificate Validity
        is_valid = tls_data.get('is_valid', False)
        is_expired = tls_data.get('is_expired', False)
        is_self_signed = tls_data.get('is_self_signed', False)
        days_remaining = tls_data.get('days_remaining', 0)
        protocol = tls_data.get('protocol_version', '')
        sig_alg = tls_data.get('signature_algorithm', '')

        if is_expired:
            score -= 60
            findings.append(self._make_finding(
                title="TLS Certificate Has Expired",
                category="ssl",
                severity="critical",
                status="fail",
                score_impact=-60,
                kb_key="TLS_CERTIFICATE",
                description=f"The SSL/TLS certificate expired on {tls_data.get('valid_until')}.",
                evidence={"valid_until": tls_data.get('valid_until'), "days_remaining": days_remaining}
            ))
        elif is_self_signed:
            score -= 40
            findings.append(self._make_finding(
                title="Self-Signed Certificate Detected",
                category="ssl",
                severity="high",
                status="fail",
                score_impact=-40,
                kb_key="TLS_CERTIFICATE",
                description="The certificate issuer matches the subject, indicating a self-signed or untrusted root certificate.",
                evidence={"issuer": tls_data.get('issuer'), "subject": tls_data.get('subject')}
            ))
        elif days_remaining < 15:
            score -= 20
            findings.append(self._make_finding(
                title="TLS Certificate Expiring Very Soon",
                category="ssl",
                severity="high",
                status="warning",
                score_impact=-20,
                kb_key="TLS_CERTIFICATE",
                description=f"The SSL/TLS certificate will expire in {days_remaining} days ({tls_data.get('valid_until')}).",
                evidence={"days_remaining": days_remaining, "valid_until": tls_data.get('valid_until')}
            ))
        elif days_remaining < 30:
            score -= 10
            findings.append(self._make_finding(
                title="TLS Certificate Expiring Within 30 Days",
                category="ssl",
                severity="medium",
                status="warning",
                score_impact=-10,
                kb_key="TLS_CERTIFICATE",
                description=f"The certificate will expire in {days_remaining} days.",
                evidence={"days_remaining": days_remaining}
            ))
        else:
            findings.append(self._make_finding(
                title="Valid TLS/SSL Certificate",
                category="ssl",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="TLS_CERTIFICATE",
                description=f"Certificate is cryptographically valid from a recognized CA with {days_remaining} days remaining.",
                evidence={
                    "issuer": tls_data.get('issuer', {}).get('commonName', 'Unknown CA'),
                    "valid_until": tls_data.get('valid_until'),
                    "days_remaining": days_remaining
                }
            ))

        # Protocol version
        if protocol in ('TLSv1.3', 'TLSv1.2'):
            findings.append(self._make_finding(
                title=f"Modern Protocol Supported ({protocol})",
                category="ssl",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="TLS_VERSION",
                description=f"Server negotiates modern, secure protocol {protocol}.",
                evidence={"protocol": protocol, "cipher": tls_data.get('cipher_suite')}
            ))
        else:
            score -= 30
            findings.append(self._make_finding(
                title="Legacy or Insecure TLS Protocol Negotiated",
                category="ssl",
                severity="high",
                status="fail",
                score_impact=-30,
                kb_key="TLS_VERSION",
                description=f"Server negotiated {protocol}, which may expose communications to cryptographic attacks.",
                evidence={"protocol": protocol}
            ))

        # Signature Algorithm check (SHA-1 / MD5)
        if 'sha1' in sig_alg.lower() or 'md5' in sig_alg.lower():
            score -= 35
            findings.append(self._make_finding(
                title="Deprecated Signature Algorithm Detected",
                category="ssl",
                severity="high",
                status="fail",
                score_impact=-35,
                kb_key="TLS_CERTIFICATE",
                description=f"Certificate uses a weak signature algorithm ({sig_alg}).",
                evidence={"algorithm": sig_alg}
            ))

        return max(0.0, score), findings

    def _evaluate_cookies(self, cookies: list) -> tuple[float, list]:
        score = 100.0
        findings = []

        if not cookies:
            findings.append(self._make_finding(
                title="No Set-Cookie Headers on Initial Response",
                category="cookies",
                severity="info",
                status="pass",
                score_impact=0,
                kb_key="COOKIE_SECURITY",
                description="The server did not issue cookies on initial unauthenticated request, minimizing cookie attack surface.",
                evidence={"cookies_count": 0}
            ))
            return 100.0, findings

        insecure_cookies = []
        no_httponly_cookies = []
        no_samesite_cookies = []

        for c in cookies:
            cname = c.get('name', 'unnamed')
            if not c.get('secure'):
                insecure_cookies.append(cname)
            if not c.get('httponly'):
                no_httponly_cookies.append(cname)
            if not c.get('samesite'):
                no_samesite_cookies.append(cname)

        if insecure_cookies:
            deduction = min(40, len(insecure_cookies) * 20)
            score -= deduction
            findings.append(self._make_finding(
                title="Cookies Missing 'Secure' Flag",
                category="cookies",
                severity="high",
                status="fail",
                score_impact=-deduction,
                kb_key="COOKIE_SECURITY",
                description=f"{len(insecure_cookies)} cookie(s) lack the Secure flag ({', '.join(insecure_cookies[:4])}), allowing plaintext transmission over HTTP.",
                evidence={"cookies": insecure_cookies}
            ))
        else:
            findings.append(self._make_finding(
                title="All Cookies Enforce 'Secure' Flag",
                category="cookies",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="COOKIE_SECURITY",
                description="All detected cookies include the Secure attribute, preventing unencrypted transport.",
                evidence={"total_cookies": len(cookies)}
            ))

        if no_httponly_cookies:
            deduction = min(30, len(no_httponly_cookies) * 15)
            score -= deduction
            findings.append(self._make_finding(
                title="Cookies Missing 'HttpOnly' Flag",
                category="cookies",
                severity="medium",
                status="warning",
                score_impact=-deduction,
                kb_key="COOKIE_SECURITY",
                description=f"{len(no_httponly_cookies)} cookie(s) lack HttpOnly ({', '.join(no_httponly_cookies[:4])}), exposing them to XSS script theft.",
                evidence={"cookies": no_httponly_cookies}
            ))
        else:
            findings.append(self._make_finding(
                title="All Cookies Enforce 'HttpOnly' Flag",
                category="cookies",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="COOKIE_SECURITY",
                description="All cookies enforce HttpOnly, mitigating credential exfiltration via Cross-Site Scripting.",
                evidence={"total_cookies": len(cookies)}
            ))

        if no_samesite_cookies:
            deduction = min(30, len(no_samesite_cookies) * 10)
            score -= deduction
            findings.append(self._make_finding(
                title="Cookies Missing 'SameSite' Attribute",
                category="cookies",
                severity="low",
                status="warning",
                score_impact=-deduction,
                kb_key="COOKIE_SECURITY",
                description=f"{len(no_samesite_cookies)} cookie(s) lack explicit SameSite attribute (Lax/Strict), increasing CSRF vulnerability.",
                evidence={"cookies": no_samesite_cookies}
            ))
        else:
            findings.append(self._make_finding(
                title="All Cookies Specify 'SameSite' Attribute",
                category="cookies",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="COOKIE_SECURITY",
                description="Cookies define explicit SameSite restrictions (Strict or Lax), protecting against cross-site request forgery.",
                evidence={"total_cookies": len(cookies)}
            ))

        return max(0.0, score), findings

    def _evaluate_dns(self, dns_data: dict) -> tuple[float, list]:
        score = 100.0
        findings = []

        # 1. SPF Check (35 points)
        if dns_data.get('spf_valid'):
            spf_val = dns_data.get('spf_record', '')
            findings.append(self._make_finding(
                title="Sender Policy Framework (SPF) Active",
                category="dns",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="SPF_RECORD",
                description="Valid SPF TXT record defined to prevent email spoofing of your domain.",
                evidence={"spf": spf_val}
            ))
        else:
            score -= 35
            findings.append(self._make_finding(
                title="Missing SPF Record (Email Spoofing Risk)",
                category="dns",
                severity="high",
                status="fail",
                score_impact=-35,
                kb_key="SPF_RECORD",
                description="No SPF record found in DNS TXT entries. Attackers can forge emails from this domain.",
                evidence={"status": "v=spf1 not detected in TXT records"}
            ))

        # 2. DMARC Check (35 points)
        if dns_data.get('dmarc_valid'):
            dmarc_policy = dns_data.get('dmarc_policy', 'none')
            if dmarc_policy in ('reject', 'quarantine'):
                findings.append(self._make_finding(
                    title=f"DMARC Enforcement Active (Policy: {dmarc_policy})",
                    category="dns",
                    severity="pass",
                    status="pass",
                    score_impact=0,
                    kb_key="DMARC_RECORD",
                    description=f"DMARC is configured with strict policy '{dmarc_policy}', blocking unauthenticated messages.",
                    evidence={"policy": dmarc_policy, "record": dns_data.get('dmarc_record')}
                ))
            else:
                score -= 10
                findings.append(self._make_finding(
                    title="DMARC Policy Set to 'none' (Monitoring Only)",
                    category="dns",
                    severity="low",
                    status="warning",
                    score_impact=-10,
                    kb_key="DMARC_RECORD",
                    description="DMARC record exists but policy is 'p=none', which logs reports but does not block spoofed emails.",
                    evidence={"record": dns_data.get('dmarc_record')}
                ))
        else:
            score -= 35
            findings.append(self._make_finding(
                title="Missing DMARC Record",
                category="dns",
                severity="high",
                status="fail",
                score_impact=-35,
                kb_key="DMARC_RECORD",
                description="No DMARC policy found at _dmarc.<domain>. Domain lacks protection against brand impersonation.",
                evidence={"status": "DNS TXT record missing at _dmarc"}
            ))

        # 3. CAA Check (20 points)
        if dns_data.get('has_caa'):
            findings.append(self._make_finding(
                title="Certification Authority Authorization (CAA) Configured",
                category="dns",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="CAA_RECORD",
                description="CAA records restrict unauthorized CAs from issuing certificates for this domain.",
                evidence={"records": dns_data.get('caa_records')}
            ))
        else:
            score -= 20
            findings.append(self._make_finding(
                title="Missing CAA DNS Records",
                category="dns",
                severity="low",
                status="warning",
                score_impact=-20,
                kb_key="CAA_RECORD",
                description="No CAA records found in DNS. Any public CA can issue certificates for this domain.",
                evidence={"status": "No CAA records found"}
            ))

        # 4. DNSSEC Check (10 points)
        if dns_data.get('has_dnssec'):
            findings.append(self._make_finding(
                title="DNSSEC Enabled",
                category="dns",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="DNSSEC",
                description="DNS responses are cryptographically signed, mitigating DNS cache poisoning.",
                evidence={"dnssec": True}
            ))
        else:
            score -= 10
            findings.append(self._make_finding(
                title="DNSSEC Not Detected",
                category="dns",
                severity="info",
                status="info",
                score_impact=-10,
                kb_key="DNSSEC",
                description="Domain does not publish DNSSEC cryptographic keys.",
                evidence={"dnssec": False}
            ))

        return max(0.0, score), findings

    def _evaluate_infrastructure(self, http_data: dict) -> tuple[float, list]:
        score = 100.0
        findings = []

        # 1. HTTP to HTTPS Redirection (50 points)
        if http_data.get('http_to_https_redirect'):
            findings.append(self._make_finding(
                title="Automatic HTTP to HTTPS Redirection Active",
                category="infrastructure",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="HTTPS_REDIRECT",
                description="Insecure HTTP requests on port 80 are automatically redirected to HTTPS.",
                evidence={"redirection": "Port 80 -> Port 443 301/302"}
            ))
        else:
            score -= 50
            findings.append(self._make_finding(
                title="Insecure HTTP Does Not Redirect to HTTPS",
                category="infrastructure",
                severity="high",
                status="fail",
                score_impact=-50,
                kb_key="HTTPS_REDIRECT",
                description="Port 80 unencrypted requests are not automatically upgraded to HTTPS.",
                evidence={"status": "No automatic HTTPS redirect found"}
            ))

        # 2. Server Information Disclosure (50 points)
        disclosures = http_data.get('disclosure_headers', {})
        if disclosures:
            score -= 50
            details = ", ".join([f"{k}: {v}" for k, v in disclosures.items()])
            findings.append(self._make_finding(
                title="Server Information / Technology Banner Disclosed",
                category="infrastructure",
                severity="medium",
                status="warning",
                score_impact=-50,
                kb_key="SERVER_DISCLOSURE",
                description=f"Server reveals technology stack or software version via headers: {details}.",
                evidence=disclosures
            ))
        else:
            findings.append(self._make_finding(
                title="Server Version Information Masked",
                category="infrastructure",
                severity="pass",
                status="pass",
                score_impact=0,
                kb_key="SERVER_DISCLOSURE",
                description="No revealing technology stack version headers detected.",
                evidence={"disclosure_headers": "None"}
            ))

        return max(0.0, score), findings

    def _make_finding(self, title: str, category: str, severity: str, status: str,
                      score_impact: int, kb_key: str, description: str, evidence: dict) -> dict:
        kb_entry = KNOWLEDGE_BASE.get(kb_key, {})
        snippets = kb_entry.get('snippets', {})
        # Format snippets as combined text or primary snippet
        snippet_text = ""
        for name, snip in snippets.items():
            snippet_text += f"# --- {name} ---\n{snip}\n\n"

        return {
            'title': title,
            'category': category,
            'severity': severity,
            'status': status,
            'score_impact': score_impact,
            'description': description or kb_entry.get('description', ''),
            'impact': kb_entry.get('impact', 'Potential security compromise or information exposure.'),
            'remediation': kb_entry.get('remediation', 'Implement recommended security controls.'),
            'remediation_code': snippet_text.strip(),
            'evidence': evidence,
            'owasp_category': kb_entry.get('owasp', 'A05:2021-Security Misconfiguration'),
            'cwe_id': kb_entry.get('cwe', 'CWE-693'),
        }
