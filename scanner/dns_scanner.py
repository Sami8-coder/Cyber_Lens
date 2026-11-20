import dns.resolver
import dns.exception

class DNSScanner:
    """
    Performs passive DNS queries and email security posture checks:
    - A and AAAA record resolution
    - MX records
    - SPF record analysis (in TXT records)
    - DMARC record analysis (at _dmarc.<domain>)
    - CAA records (Certificate Authority Authorization)
    - DNSSEC detection
    """

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    def scan(self, hostname: str) -> dict:
        results = {
            'hostname': hostname,
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'txt_records': [],
            'ns_records': [],
            'caa_records': [],
            'spf_record': None,
            'spf_valid': False,
            'dmarc_record': None,
            'dmarc_policy': None,
            'dmarc_valid': False,
            'has_caa': False,
            'has_dnssec': False,
            'error': None,
        }

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        # 1. Query A records
        try:
            answers = resolver.resolve(hostname, 'A')
            results['a_records'] = [str(r) for r in answers]
        except Exception:
            pass

        # 2. Query AAAA records (IPv6)
        try:
            answers = resolver.resolve(hostname, 'AAAA')
            results['aaaa_records'] = [str(r) for r in answers]
        except Exception:
            pass

        # 3. Query MX records
        try:
            answers = resolver.resolve(hostname, 'MX')
            results['mx_records'] = [f"{r.preference} {r.exchange}" for r in answers]
        except Exception:
            pass

        # 4. Query NS records
        try:
            answers = resolver.resolve(hostname, 'NS')
            results['ns_records'] = [str(r) for r in answers]
        except Exception:
            pass

        # 5. Query TXT records (look for SPF)
        try:
            answers = resolver.resolve(hostname, 'TXT')
            for r in answers:
                txt_val = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in r.strings])
                results['txt_records'].append(txt_val)
                if txt_val.startswith('v=spf1'):
                    results['spf_record'] = txt_val
                    results['spf_valid'] = True
        except Exception:
            pass

        # 6. Query DMARC record at _dmarc.<hostname>
        # For subdomains, check subdomain then parent domain
        dmarc_target = f"_dmarc.{hostname}"
        try:
            answers = resolver.resolve(dmarc_target, 'TXT')
            for r in answers:
                txt_val = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in r.strings])
                if txt_val.startswith('v=DMARC1'):
                    results['dmarc_record'] = txt_val
                    results['dmarc_valid'] = True
                    # Extract policy
                    for piece in txt_val.split(';'):
                        piece = piece.strip()
                        if piece.startswith('p='):
                            results['dmarc_policy'] = piece.split('=', 1)[1].strip()
                    break
        except Exception:
            # Check parent domain if hostname is a subdomain (e.g. blog.example.com -> example.com)
            parts = hostname.split('.')
            if len(parts) > 2:
                parent_domain = ".".join(parts[-2:])
                try:
                    answers = resolver.resolve(f"_dmarc.{parent_domain}", 'TXT')
                    for r in answers:
                        txt_val = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in r.strings])
                        if txt_val.startswith('v=DMARC1'):
                            results['dmarc_record'] = txt_val
                            results['dmarc_valid'] = True
                            for piece in txt_val.split(';'):
                                piece = piece.strip()
                                if piece.startswith('p='):
                                    results['dmarc_policy'] = piece.split('=', 1)[1].strip()
                            break
                except Exception:
                    pass

        # 7. Query CAA records
        try:
            answers = resolver.resolve(hostname, 'CAA')
            results['caa_records'] = [f"{r.flags} {r.tag} \"{r.value.decode('utf-8', errors='ignore') if isinstance(r.value, bytes) else r.value}\"" for r in answers]
            results['has_caa'] = len(results['caa_records']) > 0
        except Exception:
            results['has_caa'] = False

        # 8. Test DNSSEC
        try:
            answers = resolver.resolve(hostname, 'DNSKEY')
            if len(answers) > 0:
                results['has_dnssec'] = True
        except Exception:
            results['has_dnssec'] = False

        return results
