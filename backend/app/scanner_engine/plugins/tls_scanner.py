import socket
import ssl
import time
from datetime import datetime, timezone

from app.core.logging import get_logger
from app.scanner_engine.base import BaseScanner, ScanResult, ScanTarget

logger = get_logger("tls_scanner")


class TLSScanner(BaseScanner):
    name = "tls"
    category = "tls"
    timeout_seconds = 30

    WEAK_CIPHERS = {
        "NULL",
        "EXPORT",
        "DES",
        "MD5",
        "RC4",
        "aNULL",
        "eNULL",
        "ADH",
        "AECDH",
        "PSK",
        "SRP",
        "CAMELLIA-128",
        "3DES",
        "IDEA",
        "SEED",
        "RC2",
    }

    WEAK_PROTOCOLS = {
        ssl.PROTOCOL_SSLv2: "SSLv2",
        ssl.PROTOCOL_SSLv3: "SSLv3",
        ssl.PROTOCOL_TLSv1: "TLSv1.0",
        ssl.PROTOCOL_TLSv1_1: "TLSv1.1",
    }

    async def scan(self, target: ScanTarget) -> ScanResult:
        result = self.create_result()

        if target.scheme != "https":
            result.add_finding(
                title="Site does not use HTTPS",
                description="The target URL uses HTTP instead of HTTPS. All data transmitted is unencrypted and vulnerable to interception.",
                severity="critical",
                confidence="high",
                recommendation="Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.",
                score_impact=-20.0,
            )
            return result

        try:
            self._check_certificate(target, result)
            self._check_protocols(target, result)
            self._check_ciphers(target, result)
            self._check_hsts_preload(target, result)
        except Exception as e:
            logger.warning("tls_scan_error", error=str(e), hostname=target.hostname)
            result.add_finding(
                title="TLS scan could not complete",
                description=f"Error during TLS analysis: {str(e)}",
                severity="info",
                confidence="medium",
            )

        return result

    def _check_certificate(self, target: ScanTarget, result: ScanResult) -> None:
        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (target.hostname, target.port), timeout=self.timeout_seconds
            ) as sock:
                with context.wrap_socket(sock, server_hostname=target.hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    result.raw_data["tls_version"] = version
                    result.raw_data["cipher"] = cipher[0] if cipher else None
                    result.raw_data["certificate"] = {
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "not_after": cert.get("notAfter"),
                        "not_before": cert.get("notBefore"),
                        "serial_number": cert.get("serialNumber"),
                        "subject_alt_name": cert.get("subjectAltName"),
                    }

                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        not_after = datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        days_until_expiry = (not_after - datetime.now(timezone.utc)).days

                        if days_until_expiry < 0:
                            result.add_finding(
                                title="TLS certificate has expired",
                                description=f"The TLS certificate expired {abs(days_until_expiry)} days ago. Browsers will show security warnings.",
                                severity="critical",
                                confidence="high",
                                recommendation="Renew and install a new TLS certificate immediately.",
                                score_impact=-15.0,
                                evidence={
                                    "expiry_date": not_after_str,
                                    "days_overdue": abs(days_until_expiry),
                                },
                            )
                        elif days_until_expiry < 7:
                            result.add_finding(
                                title="TLS certificate expiring soon",
                                description=f"The TLS certificate expires in {days_until_expiry} days.",
                                severity="high",
                                confidence="high",
                                recommendation="Renew the TLS certificate before it expires.",
                                score_impact=-5.0,
                                evidence={"days_until_expiry": days_until_expiry},
                            )
                        elif days_until_expiry < 30:
                            result.add_finding(
                                title="TLS certificate expires within 30 days",
                                description=f"The TLS certificate expires in {days_until_expiry} days.",
                                severity="medium",
                                confidence="high",
                                recommendation="Plan certificate renewal soon.",
                                score_impact=-2.0,
                                evidence={"days_until_expiry": days_until_expiry},
                            )

                    issuer = cert.get("issuer")
                    if issuer:
                        org = None
                        for item in issuer:
                            for k, v in item:
                                if k == "organizationName":
                                    org = v
                                    break
                        if org:
                            if "Let's Encrypt" in org:
                                pass
                            result.raw_data["issuer_org"] = org

                    subject = cert.get("subject")
                    if subject:
                        cn = None
                        for item in subject:
                            for k, v in item:
                                if k == "commonName":
                                    cn = v
                                    break
                        if cn and cn != target.hostname and not self._wildcard_match(
                            cn, target.hostname
                        ):
                            san = cert.get("subjectAltName", [])
                            san_hosts = [v for t, v in san if t == "DNS"]
                            if target.hostname not in san_hosts:
                                result.add_finding(
                                    title="TLS certificate hostname mismatch",
                                    description=f"Certificate is for '{cn}' but target is '{target.hostname}'.",
                                    severity="high",
                                    confidence="high",
                                    recommendation="Use a certificate valid for the target hostname.",
                                    score_impact=-10.0,
                                )

        except ssl.SSLError as e:
            if "certificate verify failed" in str(e).lower():
                result.add_finding(
                    title="TLS certificate verification failed",
                    description="The TLS certificate could not be verified. This may indicate a self-signed or untrusted certificate.",
                    severity="high",
                    confidence="high",
                    recommendation="Use a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.)",
                    score_impact=-10.0,
                )
            else:
                result.add_finding(
                    title="TLS/SSL error",
                    description=f"SSL error: {str(e)}",
                    severity="medium",
                    confidence="medium",
                    recommendation="Check TLS configuration.",
                    score_impact=-3.0,
                )
        except socket.timeout:
            result.add_finding(
                title="TLS connection timeout",
                description="Could not establish TLS connection within timeout period.",
                severity="low",
                confidence="medium",
            )
        except Exception as e:
            logger.warning("certificate_check_error", error=str(e))

    def _check_protocols(self, target: ScanTarget, result: ScanResult) -> None:
        protocols_to_test = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ]

        for proto_name, proto_version in protocols_to_test:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = proto_version
                context.maximum_version = proto_version
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection(
                    (target.hostname, target.port), timeout=5
                ) as sock:
                    with context.wrap_socket(sock, server_hostname=target.hostname):
                        result.add_finding(
                            title=f"Weak TLS protocol enabled: {proto_name}",
                            description=f"{proto_name} is enabled and can be negotiated. This protocol has known vulnerabilities.",
                            severity="high",
                            confidence="medium",
                            recommendation=f"Disable {proto_name} and enforce TLSv1.2 or higher.",
                            score_impact=-8.0,
                            evidence={"protocol": proto_name},
                        )
            except (ssl.SSLError, socket.error, OSError):
                pass
            except Exception as e:
                logger.debug("protocol_test_error", protocol=proto_name, error=str(e))

    def _check_ciphers(self, target: ScanTarget, result: ScanResult) -> None:
        weak_ciphers_found = []
        common_weak = [
            "RC4-SHA",
            "DES-CBC3-SHA",
            "NULL",
            "EXPORT",
            "aNULL",
            "eNULL",
        ]

        for cipher in common_weak:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.set_ciphers(cipher)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection(
                    (target.hostname, target.port), timeout=5
                ) as sock:
                    with context.wrap_socket(
                        sock, server_hostname=target.hostname
                    ) as ssock:
                        weak_ciphers_found.append(ssock.cipher()[0])
            except (ssl.SSLError, socket.error, OSError):
                pass

        if weak_ciphers_found:
            result.add_finding(
                title="Weak cipher suites enabled",
                description=f"The following weak cipher suites are enabled: {', '.join(weak_ciphers_found)}. These use deprecated algorithms vulnerable to attacks.",
                severity="high",
                confidence="medium",
                recommendation="Disable weak ciphers and only allow strong cipher suites like AES-GCM and ChaCha20-Poly1305.",
                score_impact=-8.0,
                evidence={"weak_ciphers": weak_ciphers_found},
            )

    def _check_hsts_preload(self, target: ScanTarget, result: ScanResult) -> None:
        import httpx

        try:
            with httpx.Client(verify=False, timeout=10, follow_redirects=True) as client:
                response = client.head(f"https://{target.hostname}")
                hsts = response.headers.get("strict-transport-security")
                if hsts:
                    if "preload" in hsts.lower():
                        pass
                    else:
                        result.add_finding(
                            title="HSTS preload not requested",
                            description="HSTS header is present but does not include the 'preload' directive. Preloading ensures HSTS is enforced even on first visit.",
                            severity="low",
                            confidence="high",
                            recommendation="Add 'preload' to HSTS and submit to hstspreload.org.",
                            score_impact=-1.0,
                        )
        except Exception:
            pass

    def _wildcard_match(self, pattern: str, hostname: str) -> bool:
        if pattern.startswith("*."):
            base = pattern[2:]
            return hostname.endswith(f".{base}") or hostname == base
        return pattern == hostname
