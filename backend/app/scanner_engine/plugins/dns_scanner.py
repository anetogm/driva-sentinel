import dns.resolver
import dns.zone
from dns.exception import DNSException

from app.core.logging import get_logger
from app.scanner_engine.base import BaseScanner, ScanResult, ScanTarget

logger = get_logger("dns_scanner")


class DNSScanner(BaseScanner):
    name = "dns"
    category = "dns"
    timeout_seconds = 30

    async def scan(self, target: ScanTarget) -> ScanResult:
        result = self.create_result()
        hostname = target.hostname

        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 15

        self._check_spf(hostname, resolver, result)
        self._check_dmarc(hostname, resolver, result)
        self._check_dkim(hostname, resolver, result)
        self._check_dnssec(hostname, resolver, result)
        self._check_caa(hostname, resolver, result)
        self._check_mx(hostname, resolver, result)
        self._check_wildcard(hostname, resolver, result)
        self._check_subdomains(hostname, resolver, result)

        return result

    def _check_spf(self, hostname: str, resolver: dns.resolver.Resolver, result: ScanResult) -> None:
        try:
            answers = resolver.resolve(hostname, "TXT")
            spf_records = [str(r) for r in answers if "v=spf1" in str(r)]

            if not spf_records:
                result.add_finding(
                    title="Missing SPF record",
                    description="No SPF (Sender Policy Framework) record found. Without SPF, attackers can spoof emails from your domain.",
                    severity="medium",
                    confidence="high",
                    recommendation="Add an SPF record: v=spf1 include:_spf.google.com ~all (adjust to your mail provider).",
                    score_impact=-5.0,
                )
            else:
                spf = spf_records[0]
                result.raw_data["spf_record"] = spf
                if "+all" in spf or "all" not in spf:
                    result.add_finding(
                        title="SPF record allows all senders",
                        description="The SPF record does not properly restrict senders. '+all' or missing 'all' mechanism allows any server to send email as your domain.",
                        severity="high",
                        confidence="high",
                        recommendation="Use '-all' (hard fail) or '~all' (soft fail) at the end of your SPF record.",
                        score_impact=-8.0,
                        evidence={"spf_record": spf},
                    )
                if "?all" in spf:
                    result.add_finding(
                        title="SPF record uses neutral all",
                        description="SPF uses '?all' which is a neutral mechanism and does not provide strong protection against spoofing.",
                        severity="low",
                        confidence="high",
                        recommendation="Use '-all' or '~all' for stronger protection.",
                        score_impact=-2.0,
                        evidence={"spf_record": spf},
                    )
        except (DNSException, Exception) as e:
            logger.debug("spf_check_error", error=str(e))
            result.add_finding(
                title="Could not verify SPF record",
                description=f"SPF check failed: {str(e)}",
                severity="info",
                confidence="low",
            )

    def _check_dmarc(self, hostname: str, resolver: dns.resolver.Resolver, result: ScanResult) -> None:
        try:
            answers = resolver.resolve(f"_dmarc.{hostname}", "TXT")
            dmarc_records = [str(r) for r in answers if "v=DMARC1" in str(r)]

            if not dmarc_records:
                result.add_finding(
                    title="Missing DMARC record",
                    description="No DMARC record found. DMARC protects against email spoofing and phishing by defining how receivers should handle failed SPF/DKIM checks.",
                    severity="medium",
                    confidence="high",
                    recommendation="Add a DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
                    score_impact=-5.0,
                )
            else:
                dmarc = dmarc_records[0]
                result.raw_data["dmarc_record"] = dmarc
                if "p=none" in dmarc.lower():
                    result.add_finding(
                        title="DMARC policy is set to none",
                        description="DMARC policy is 'p=none' which means receivers take no action on failed authentication. This provides monitoring only.",
                        severity="medium",
                        confidence="high",
                        recommendation="Upgrade to p=quarantine or p=reject after monitoring.",
                        score_impact=-3.0,
                        evidence={"dmarc_record": dmarc},
                    )
                if "pct=" in dmarc.lower():
                    import re
                    pct_match = re.search(r'pct=(\d+)', dmarc, re.IGNORECASE)
                    if pct_match:
                        pct = int(pct_match.group(1))
                        if pct < 100:
                            result.add_finding(
                                title="DMARC policy not applied to all emails",
                                description=f"DMARC pct is set to {pct}%, meaning only {pct}% of failed emails are affected by the policy.",
                                severity="low",
                                confidence="high",
                                recommendation="Set pct=100 for full enforcement.",
                                score_impact=-1.0,
                            )
                if "rua=" not in dmarc.lower():
                    result.add_finding(
                        title="DMARC missing aggregate report address",
                        description="No rua (aggregate report) address in DMARC. You won't receive reports about authentication failures.",
                        severity="low",
                        confidence="high",
                        recommendation="Add rua=mailto:dmarc-reports@yourdomain.com to receive aggregate reports.",
                        score_impact=-1.0,
                    )
        except (DNSException, Exception) as e:
            logger.debug("dmarc_check_error", error=str(e))
            result.add_finding(
                title="Missing DMARC record",
                description="No DMARC record found at _dmarc.{hostname}",
                severity="medium",
                confidence="high",
                recommendation="Add a DMARC record for email authentication protection.",
                score_impact=-5.0,
            )

    def _check_dkim(self, hostname: str, resolver: dns.resolver.Resolver, result: ScanResult) -> None:
        common_selectors = ["default", "google", "mail", "selector1", "selector2", "dkim", "smtp"]
        found_dkim = False

        for selector in common_selectors:
            try:
                answers = resolver.resolve(f"{selector}._domainkey.{hostname}", "TXT")
                dkim_records = [str(r) for r in answers if "v=DKIM1" in str(r)]
                if dkim_records:
                    found_dkim = True
                    result.raw_data["dkim_selectors"] = result.raw_data.get("dkim_selectors", []) + [selector]
            except (DNSException, Exception):
                continue

        if not found_dkim:
            result.add_finding(
                title="DKIM record not detected",
                description="No DKIM record found with common selectors. DKIM cryptographically signs emails to verify sender authenticity.",
                severity="low",
                confidence="medium",
                recommendation="Set up DKIM with your email provider and publish the public key in DNS.",
                score_impact=-2.0,
            )

    def _check_dnssec(self, hostname: str, resolver: dns.resolver.Resolver, result: ScanResult) -> None:
        try:
            dnssec_resolver = dns.resolver.Resolver()
            dnssec_resolver.timeout = 10
            dnssec_resolver.lifetime = 15

            try:
                answers = dnssec_resolver.resolve(hostname, "A", raise_on_no_answer=False)
                if hasattr(answers, 'response'):
                    response = answers.response
                    flags = response.flags
                    if flags & 0x8000:
                        result.raw_data["dnssec"] = "ad_flag_set"
                    else:
                        result.add_finding(
                            title="DNSSEC not validated",
                            description="DNSSEC is not enabled or not properly configured. DNS responses could be forged by attackers (DNS spoofing/cache poisoning).",
                            severity="medium",
                            confidence="medium",
                            recommendation="Enable DNSSEC for your domain at your DNS provider/registrar.",
                            score_impact=-4.0,
                        )
                else:
                    result.add_finding(
                        title="DNSSEC not detected",
                        description="Could not confirm DNSSEC validation for the domain.",
                        severity="low",
                        confidence="medium",
                        recommendation="Enable DNSSEC to protect against DNS spoofing.",
                        score_impact=-2.0,
                    )
            except Exception:
                result.add_finding(
                    title="DNSSEC not detected",
                    description="Could not verify DNSSEC configuration.",
                    severity="low",
                    confidence="low",
                    recommendation="Enable DNSSEC at your DNS provider.",
                    score_impact=-2.0,
                )
        except Exception as e:
            logger.debug("dnssec_check_error", error=str(e))

    def _check_caa(self, hostname: str, resolver: dns.resolver.Resolver, result: ScanResult) -> None:
        try:
            answers = resolver.resolve(hostname, "CAA")
            caa_records = [str(r) for r in answers]
            result.raw_data["caa_records"] = caa_records

            if not caa_records:
                result.add_finding(
                    title="Missing CAA record",
                    description="No CAA (Certificate Authority Authorization) record found. Without CAA, any CA can issue certificates for your domain.",
                    severity="low",
                    confidence="high",
                    recommendation="Add CAA records to restrict which CAs can issue certificates: 0 issue 'letsencrypt.org'; 0 issuewild 'letsencrypt.org'",
                    score_impact=-2.0,
                )
            else:
                has_issue = any("issue " in r for r in caa_records)
                has_issuewild = any("issuewild " in r for r in caa_records)
                if not has_issuewild:
                    result.add_finding(
                        title="CAA missing issuewild directive",
                        description="CAA records exist but no issuewild directive found. Wildcard certificates can be issued by any CA.",
                        severity="low",
                        confidence="medium",
                        recommendation="Add issuewild directive to control wildcard certificate issuance.",
                        score_impact=-1.0,
                    )
        except (DNSException, Exception):
            result.add_finding(
                title="Missing CAA record",
                description="No CAA record found. Any CA can issue certificates for this domain.",
                severity="low",
                confidence="high",
                recommendation="Add CAA records to restrict certificate issuance.",
                score_impact=-2.0,
            )

    def _check_mx(self, hostname: str, resolver: dns.resolver.Resolver, result: ScanResult) -> None:
        try:
            answers = resolver.resolve(hostname, "MX")
            mx_records = [(r.preference, str(r.exchange).rstrip('.')) for r in answers]
            result.raw_data["mx_records"] = mx_records

            if mx_records:
                result.raw_data["has_mail"] = True
        except (DNSException, Exception):
            result.raw_data["has_mail"] = False

    def _check_wildcard(self, hostname: str, resolver: dns.resolver.Resolver, result: ScanResult) -> None:
        try:
            wildcard_query = f"random-{hash(hostname) % 1000000:06d}.{hostname}"
            try:
                answers = resolver.resolve(wildcard_query, "A")
                if answers:
                    result.add_finding(
                        title="Wildcard DNS record detected",
                        description="A wildcard DNS record (*.domain) is configured. This can increase the attack surface by resolving arbitrary subdomains.",
                        severity="low",
                        confidence="medium",
                        recommendation="Remove wildcard DNS records if not strictly necessary. Use explicit subdomain records instead.",
                        score_impact=-1.0,
                    )
                    result.raw_data["wildcard"] = True
            except DNSException:
                result.raw_data["wildcard"] = False
        except Exception as e:
            logger.debug("wildcard_check_error", error=str(e))

    def _check_subdomains(self, hostname: str, resolver: dns.resolver.Resolver, result: ScanResult) -> None:
        common_subdomains = [
            "www", "mail", "ftp", "admin", "api", "blog", "shop",
            "test", "dev", "staging", "demo", "portal", "vpn",
            "remote", "support", "docs", "app", "mobile", "cdn",
        ]
        found = []

        for sub in common_subdomains:
            try:
                subdomain = f"{sub}.{hostname}"
                answers = resolver.resolve(subdomain, "A")
                if answers:
                    found.append({"subdomain": subdomain, "ips": [str(r) for r in answers]})
            except (DNSException, Exception):
                continue

        if found:
            result.raw_data["discovered_subdomains"] = found
            if len(found) > 5:
                result.add_finding(
                    title="Multiple subdomains discovered",
                    description=f"Found {len(found)} subdomains. Each exposed subdomain is a potential attack surface.",
                    severity="info",
                    confidence="medium",
                    recommendation="Ensure all subdomains are properly secured and regularly audited.",
                    score_impact=-0.5,
                    evidence={"subdomains": [f["subdomain"] for f in found]},
                )
