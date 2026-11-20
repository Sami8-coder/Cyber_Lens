"""
CyberLens Security Knowledge Base & Remediation Catalog.
Provides explainable findings with industry-standard references (OWASP 2021, CWE),
risk impacts, and production-ready configuration snippets.
"""

KNOWLEDGE_BASE = {
    'HSTS': {
        'title': 'HTTP Strict Transport Security (HSTS)',
        'category': 'headers',
        'cwe': 'CWE-319: Cleartext Transmission of Sensitive Information',
        'owasp': 'A05:2021-Security Misconfiguration',
        'description': 'HSTS informs browsers that the site should only be accessed using HTTPS, and that any future attempts to access it using HTTP should automatically be converted to HTTPS.',
        'impact': 'Without HSTS, visitors are vulnerable to man-in-the-middle (MitM) SSL-stripping attacks, where an attacker intercepts unencrypted HTTP requests before redirection occurs.',
        'remediation': 'Configure the Strict-Transport-Security header with a minimum max-age of 31536000 seconds (1 year), includeSubDomains, and preload.',
        'snippets': {
            'Nginx': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            'Apache': 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            'Django': 'SECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True\nSECURE_HSTS_PRELOAD = True',
            'Cloudflare': 'Enable HSTS in Cloudflare SSL/TLS tab -> Edge Certificates -> Enable HSTS (max-age 12 months, include subdomains, preload).'
        }
    },
    'CSP': {
        'title': 'Content Security Policy (CSP)',
        'category': 'headers',
        'cwe': 'CWE-1021: Improper Restriction of Rendered UI Layers or Scripts',
        'owasp': 'A03:2021-Injection',
        'description': 'Content Security Policy (CSP) is an added layer of security that helps detect and mitigate Cross-Site Scripting (XSS), clickjacking, and data injection attacks by restricting allowed origins for scripts, styles, and frames.',
        'impact': 'Missing or overly permissive CSP allows attackers to execute malicious scripts in user browsers, exfiltrate credentials or tokens, and inject unwanted elements.',
        'remediation': 'Define a strict Content-Security-Policy starting with default-src \'self\', avoiding unsafe-inline or unsafe-eval unless strictly necessary with nonces/hashes.',
        'snippets': {
            'Nginx': 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' https://cdn.jsdelivr.net; style-src \'self\' \'unsafe-inline\' https://cdn.jsdelivr.net; img-src \'self\' data: https:; font-src \'self\' https: data:; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\';" always;',
            'Apache': 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; frame-ancestors \'none\';"',
            'Django': 'Install django-csp and configure:\nCSP_DEFAULT_SRC = ("\'self\'",)\nCSP_SCRIPT_SRC = ("\'self\'",)\nCSP_STYLE_SRC = ("\'self\'", "\'unsafe-inline\'")\nCSP_OBJECT_SRC = ("\'none\'",)'
        }
    },
    'X_FRAME_OPTIONS': {
        'title': 'X-Frame-Options (Clickjacking Protection)',
        'category': 'headers',
        'cwe': 'CWE-1021: Improper Restriction of Rendered UI Layers or Frames',
        'owasp': 'A05:2021-Security Misconfiguration',
        'description': 'The X-Frame-Options HTTP header indicates whether a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>.',
        'impact': 'Without frame restriction, malicious sites can embed your web pages into invisible iframes to execute clickjacking attacks, tricking authenticated users into making unintentional purchases or state changes.',
        'remediation': 'Send X-Frame-Options: DENY (disallows any domain from framing) or SAMEORIGIN (permits framing only by the same origin).',
        'snippets': {
            'Nginx': 'add_header X-Frame-Options "DENY" always;',
            'Apache': 'Header always set X-Frame-Options "DENY"',
            'Django': 'X_FRAME_OPTIONS = "DENY"'
        }
    },
    'X_CONTENT_TYPE_OPTIONS': {
        'title': 'X-Content-Type-Options (MIME-Sniffing Prevention)',
        'category': 'headers',
        'cwe': 'CWE-430: Deployment of Wrong Handler for Web Resource',
        'owasp': 'A05:2021-Security Misconfiguration',
        'description': 'The X-Content-Type-Options response header prevents browsers from MIME-sniffing a response away from the declared content-type.',
        'impact': 'If absent, browsers may treat user-uploaded images or text files as executable JavaScript or HTML, resulting in stored Cross-Site Scripting (XSS).',
        'remediation': 'Set X-Content-Type-Options to nosniff on all HTTP responses.',
        'snippets': {
            'Nginx': 'add_header X-Content-Type-Options "nosniff" always;',
            'Apache': 'Header always set X-Content-Type-Options "nosniff"',
            'Django': 'SECURE_CONTENT_TYPE_NOSNIFF = True'
        }
    },
    'REFERRER_POLICY': {
        'title': 'Referrer-Policy (Information Leakage Protection)',
        'category': 'headers',
        'cwe': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
        'owasp': 'A01:2021-Broken Access Control',
        'description': 'Controls how much referrer information (via the Referer header) is included with navigation and resource requests.',
        'impact': 'Default or absent policies can leak sensitive URL tokens, search queries, user IDs, or internal URL structures to external third-party servers.',
        'remediation': 'Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.',
        'snippets': {
            'Nginx': 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            'Apache': 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
            'Django': 'SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"'
        }
    },
    'PERMISSIONS_POLICY': {
        'title': 'Permissions-Policy (Browser Feature Restrictions)',
        'category': 'headers',
        'cwe': 'CWE-250: Execution with Unnecessary Privileges',
        'owasp': 'A05:2021-Security Misconfiguration',
        'description': 'Permissions-Policy allows site administrators to declare which browser APIs (camera, microphone, geolocation, payment, sensors) can be used by the page and embedded iframes.',
        'impact': 'Without feature restrictions, malicious third-party scripts or embedded ads can abuse sensor APIs or request sensitive user hardware access without owner intent.',
        'remediation': 'Explicitly disable sensitive features not required by your site.',
        'snippets': {
            'Nginx': 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;',
            'Apache': 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"'
        }
    },
    'COOP_CORP': {
        'title': 'Cross-Origin Isolation (COOP & CORP)',
        'category': 'headers',
        'cwe': 'CWE-346: Origin Validation Error',
        'owasp': 'A05:2021-Security Misconfiguration',
        'description': 'Cross-Origin-Opener-Policy (COOP) and Cross-Origin-Resource-Policy (CORP) isolate your browsing context from other origins, mitigating side-channel timing attacks (Spectre) and cross-origin leaks.',
        'impact': 'Pages opening external links or embedding cross-origin assets without isolation can be probed by malicious windows via Window.opener or shared process memory.',
        'remediation': 'Add Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Resource-Policy: same-origin.',
        'snippets': {
            'Nginx': 'add_header Cross-Origin-Opener-Policy "same-origin" always;\nadd_header Cross-Origin-Resource-Policy "same-origin" always;',
            'Apache': 'Header always set Cross-Origin-Opener-Policy "same-origin"\nHeader always set Cross-Origin-Resource-Policy "same-origin"'
        }
    },
    'SERVER_DISCLOSURE': {
        'title': 'Server & Technology Information Disclosure',
        'category': 'infrastructure',
        'cwe': 'CWE-200: Information Exposure',
        'owasp': 'A05:2021-Security Misconfiguration',
        'description': 'The server reveals specific software versions via Server, X-Powered-By, or X-AspNet-Version headers.',
        'impact': 'Detailed version disclosures (e.g. Apache/2.4.29, PHP/7.2, ASP.NET 4.0) aid malicious actors in fingerprinting exact known CVE vulnerabilities and targeting zero-day exploits.',
        'remediation': 'Disable server signature banners and remove X-Powered-By headers.',
        'snippets': {
            'Nginx': 'server_tokens off;',
            'Apache': 'ServerTokens Prod\nServerSignature Off',
            'PHP': 'expose_php = Off (in php.ini)'
        }
    },
    'COOKIE_SECURITY': {
        'title': 'Session & Cookie Security Flags',
        'category': 'cookies',
        'cwe': 'CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute',
        'owasp': 'A05:2021-Security Misconfiguration',
        'description': 'Cookies must have the Secure, HttpOnly, and SameSite attributes enabled to safeguard session tokens and authentication cookies.',
        'impact': 'Missing Secure allows plaintext transmission over HTTP. Missing HttpOnly allows XSS scripts to steal session tokens. Missing SameSite allows Cross-Site Request Forgery (CSRF).',
        'remediation': 'Set Secure=True, HttpOnly=True, and SameSite=Lax (or Strict) on all application cookies.',
        'snippets': {
            'Django': 'SESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = "Lax"',
            'PHP': 'session.cookie_secure = 1\nsession.cookie_httponly = 1\nsession.cookie_samesite = Lax'
        }
    },
    'TLS_CERTIFICATE': {
        'title': 'TLS / SSL Certificate Health & Cryptography',
        'category': 'ssl',
        'cwe': 'CWE-295: Improper Certificate Validation',
        'owasp': 'A02:2021-Cryptographic Failures',
        'description': 'Validates certificate chain validity, expiration horizon, modern signature algorithms (SHA-256+), and trusted certificate authority.',
        'impact': 'Expired, self-signed, or weak signature certificates trigger browser security warnings, block legitimate users, and break confidentiality.',
        'remediation': 'Deploy automated certificate renewal via ACME / Let\'s Encrypt or your cloud provider, maintaining at least 30 days renewal buffer.',
        'snippets': {
            'Certbot': 'certbot --nginx -d example.com --agree-tos -m admin@example.com'
        }
    },
    'TLS_VERSION': {
        'title': 'Modern TLS Protocol Version (TLS 1.2+ / TLS 1.3)',
        'category': 'ssl',
        'cwe': 'CWE-326: Inadequate Encryption Strength',
        'owasp': 'A02:2021-Cryptographic Failures',
        'description': 'Enforce TLSv1.2 and TLSv1.3 protocols and disable obsolete protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1).',
        'impact': 'Deprecated protocols suffer from known mathematical cryptographic attacks (POODLE, BEAST, DROWN) allowing attackers to decrypt HTTPS traffic.',
        'remediation': 'Configure web servers to allow only TLSv1.2 and TLSv1.3.',
        'snippets': {
            'Nginx': 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5:!3DES;',
            'Apache': 'SSLProtocol -all +TLSv1.2 +TLSv1.3'
        }
    },
    'HTTPS_REDIRECT': {
        'title': 'Automatic HTTP to HTTPS Redirection',
        'category': 'infrastructure',
        'cwe': 'CWE-319: Cleartext Transmission of Sensitive Information',
        'owasp': 'A05:2021-Security Misconfiguration',
        'description': 'All unencrypted HTTP requests on port 80 must automatically redirect to the secure HTTPS port 443 with a 301 Permanent Redirect.',
        'impact': 'If HTTP is served unencrypted, visitors may unknowingly submit form credentials or view sensitive data over open Wi-Fi networks in plaintext.',
        'remediation': 'Redirect all port 80 traffic to HTTPS.',
        'snippets': {
            'Nginx': 'server {\n    listen 80;\n    server_name example.com www.example.com;\n    return 301 https://$host$request_uri;\n}',
            'Apache': 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]',
            'Django': 'SECURE_SSL_REDIRECT = True'
        }
    },
    'SPF_RECORD': {
        'title': 'Sender Policy Framework (SPF)',
        'category': 'dns',
        'cwe': 'CWE-290: Authentication Bypass by Spoofing',
        'owasp': 'A07:2021-Identification and Authentication Failures',
        'description': 'SPF is an email validation protocol in DNS that specifies which mail servers are authorized to send email on behalf of your domain.',
        'impact': 'Missing or misconfigured SPF records allow attackers to send spoofed phishing emails appearing to originate from your legitimate domain.',
        'remediation': 'Publish a TXT record for your domain with valid sending IPs and a terminating -all or ~all mechanism.',
        'snippets': {
            'DNS TXT': 'example.com. IN TXT "v=spf1 include:_spf.google.com ~all"'
        }
    },
    'DMARC_RECORD': {
        'title': 'DMARC (Domain-based Message Authentication)',
        'category': 'dns',
        'cwe': 'CWE-290: Authentication Bypass by Spoofing',
        'owasp': 'A07:2021-Identification and Authentication Failures',
        'description': 'DMARC leverages SPF and DKIM to provide instructions to receiving mail servers on how to handle unauthenticated emails (none, quarantine, reject).',
        'impact': 'Without DMARC enforcement, phishers and cybercriminals can impersonate your brand and executive staff, bypassing spam filters and damaging domain reputation.',
        'remediation': 'Publish a DMARC TXT record at _dmarc.<yourdomain> with policy p=quarantine or p=reject.',
        'snippets': {
            'DNS TXT': '_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; pct=100"'
        }
    },
    'CAA_RECORD': {
        'title': 'Certification Authority Authorization (CAA)',
        'category': 'dns',
        'cwe': 'CWE-295: Improper Certificate Validation',
        'owasp': 'A05:2021-Security Misconfiguration',
        'description': 'CAA is a DNS record that allows domain owners to specify which Certificate Authorities (CAs) are permitted to issue SSL certificates for their domain.',
        'impact': 'Without CAA records, any compromised or rogue Certificate Authority worldwide can issue unauthorized valid SSL certificates for your domain without detection.',
        'remediation': 'Add CAA records restricting issuance to your designated certificate authorities (e.g. Let\'s Encrypt, DigiCert).',
        'snippets': {
            'DNS CAA': 'example.com. IN CAA 0 issue "letsencrypt.org"\nexample.com. IN CAA 0 iodef "mailto:security@example.com"'
        }
    },
    'DNSSEC': {
        'title': 'DNSSEC (Domain Name System Security Extensions)',
        'category': 'dns',
        'cwe': 'CWE-350: Reliance on Reverse DNS Resolution',
        'owasp': 'A05:2021-Security Misconfiguration',
        'description': 'DNSSEC strengthens DNS authentication using digital signatures based on public key cryptography.',
        'impact': 'Without DNSSEC, recursive resolvers and users are susceptible to DNS spoofing and cache poisoning attacks.',
        'remediation': 'Enable DNSSEC signing at your authoritative DNS provider and upload the DS record to your domain registrar.',
        'snippets': {
            'Registrar': 'Enable DNSSEC toggle in Cloudflare, Route53, Namecheap, or GoDaddy control panel.'
        }
    }
}
