import socket
import ipaddress
import urllib.parse
from typing import Tuple, Optional

class SSRFProtectionError(Exception):
    """Raised when a target URL resolves to an internal or forbidden address."""
    pass

class SSRFValidator:
    """
    Enforces strict SSRF protection:
    - Only allows http:// and https:// schemes.
    - Resolves hostnames to IP addresses.
    - Blocks loopback, private, link-local, multicast, reserved, and cloud metadata addresses.
    - Prevents DNS rebinding attacks.
    """

    FORBIDDEN_HOSTNAMES = {
        'localhost',
        'localhost.localdomain',
        'ip6-localhost',
        'ip6-loopback',
        'metadata.google.internal',
        'instance-data',
    }

    CLOUD_METADATA_IPS = {
        '169.254.169.254', # AWS / GCP / Azure metadata
        '100.100.100.200', # Alibaba cloud metadata
    }

    @classmethod
    def validate_and_resolve(cls, target_url: str) -> Tuple[str, str, str]:
        """
        Validates URL and resolves hostname to a safe public IP.
        Returns (normalized_url, hostname, resolved_ip).
        Raises SSRFProtectionError if unsafe.
        """
        if not target_url or not isinstance(target_url, str):
            raise SSRFProtectionError("Empty or invalid target URL provided.")

        raw_url = target_url.strip()
        if not (raw_url.startswith('http://') or raw_url.startswith('https://')):
            raw_url = 'https://' + raw_url

        try:
            parsed = urllib.parse.urlparse(raw_url)
        except Exception as e:
            raise SSRFProtectionError(f"Malformed URL: {e}")

        scheme = (parsed.scheme or '').lower()
        if scheme not in ('http', 'https'):
            raise SSRFProtectionError(f"Unsupported protocol scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

        hostname = (parsed.hostname or '').strip().lower()
        if not hostname:
            raise SSRFProtectionError("Target URL does not contain a valid hostname.")

        if hostname in cls.FORBIDDEN_HOSTNAMES or hostname.endswith('.local') or hostname.endswith('.internal'):
            raise SSRFProtectionError(f"Target host '{hostname}' is a forbidden internal or reserved name.")

        # Check for numeric or hex IP tricks
        try:
            # Resolve DNS hostname
            resolved_ips = cls._resolve_host(hostname)
        except socket.gaierror as e:
            raise SSRFProtectionError(f"DNS resolution failed for host '{hostname}': {e}")
        except Exception as e:
            raise SSRFProtectionError(f"Resolution error for '{hostname}': {e}")

        if not resolved_ips:
            raise SSRFProtectionError(f"Host '{hostname}' could not be resolved to any IP address.")

        # Validate every resolved IP address
        primary_ip = resolved_ips[0]
        for ip_str in resolved_ips:
            cls.validate_ip(ip_str, hostname)

        # Normalize URL
        path = parsed.path or '/'
        port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
        normalized_url = f"{scheme}://{hostname}{port_part}{path}"
        if parsed.query:
            normalized_url += f"?{parsed.query}"

        return normalized_url, hostname, primary_ip

    @classmethod
    def validate_ip(cls, ip_str: str, hostname: str = ""):
        """Validates that an IP is a public routable unicast IP."""
        if ip_str in cls.CLOUD_METADATA_IPS:
            raise SSRFProtectionError(f"Target '{hostname}' resolves to cloud metadata service IP ({ip_str}), which is strictly blocked.")

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFProtectionError(f"Invalid IP address representation: {ip_str}")

        if ip_obj.is_loopback:
            raise SSRFProtectionError(f"Target resolves to loopback IP ({ip_str}), which is forbidden.")

        if ip_obj.is_private:
            raise SSRFProtectionError(f"Target resolves to private network IP ({ip_str}), which is forbidden.")

        if ip_obj.is_link_local:
            raise SSRFProtectionError(f"Target resolves to link-local IP ({ip_str}), which is forbidden.")

        if ip_obj.is_multicast:
            raise SSRFProtectionError(f"Target resolves to multicast IP ({ip_str}), which is forbidden.")

        if ip_obj.is_reserved:
            raise SSRFProtectionError(f"Target resolves to IETF reserved IP ({ip_str}), which is forbidden.")

        if ip_obj.is_unspecified:
            raise SSRFProtectionError(f"Target resolves to unspecified IP (0.0.0.0 / ::), which is forbidden.")

        return True

    @classmethod
    def _resolve_host(cls, hostname: str) -> list[str]:
        """Resolves hostname to list of IPv4 and IPv6 strings."""
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = []
        for item in addr_info:
            sockaddr = item[4]
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips
