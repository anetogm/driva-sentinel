import re

import httpx

from app.core.logging import get_logger
from app.scanner_engine.base import BaseScanner, ScanResult, ScanTarget

logger = get_logger("fingerprint_scanner")


class FingerprintScanner(BaseScanner):
    name = "fingerprint"
    category = "fingerprint"
    timeout_seconds = 20

    SERVER_PATTERNS = {
        r"nginx/([\d.]+)": {"name": "nginx", "type": "web_server"},
        r"Apache/?([\d.]*)?": {"name": "Apache", "type": "web_server"},
        r"Microsoft-IIS/([\d.]+)": {"name": "IIS", "type": "web_server"},
        r"lighttpd/([\d.]+)": {"name": "lighttpd", "type": "web_server"},
        r"Caddy": {"name": "Caddy", "type": "web_server"},
        r"cloudflare": {"name": "Cloudflare", "type": "cdn"},
        r"AkamaiGHost": {"name": "Akamai", "type": "cdn"},
        r"Fastly": {"name": "Fastly", "type": "cdn"},
        r"AmazonS3": {"name": "AWS S3", "type": "cloud"},
        r"gws": {"name": "Google Web Server", "type": "cloud"},
        r"GSE": {"name": "Google App Engine", "type": "cloud"},
        r"openresty": {"name": "OpenResty", "type": "web_server"},
    }

    HEADER_FINGERPRINTS = {
        "x-aspnet-version": {"name": "ASP.NET", "type": "framework"},
        "x-aspnetmvc-version": {"name": "ASP.NET MVC", "type": "framework"},
        "x-generator": {"name": "CMS/Generator", "type": "cms"},
        "x-drupal-cache": {"name": "Drupal", "type": "cms"},
        "x-pingback": {"name": "WordPress", "type": "cms"},
        "x-country-code": {"name": "CDN", "type": "cdn"},
        "x-cache": {"name": "Caching Proxy", "type": "proxy"},
        "x-cache-hits": {"name": "Caching Proxy", "type": "proxy"},
        "x-served-by": {"name": "CDN/Proxy", "type": "proxy"},
        "x-timer": {"name": "Fastly", "type": "cdn"},
        "cf-ray": {"name": "Cloudflare", "type": "cdn"},
        "cf-cache-status": {"name": "Cloudflare", "type": "cdn"},
        "x-amz-request-id": {"name": "AWS S3", "type": "cloud"},
        "x-amz-id-2": {"name": "AWS S3", "type": "cloud"},
        "x-azure-ref": {"name": "Azure", "type": "cloud"},
        "x-ms-version": {"name": "Azure", "type": "cloud"},
    }

    COOKIE_FINGERPRINTS = {
        "PHPSESSID": {"name": "PHP", "type": "language"},
        "sessionid": {"name": "Django", "type": "framework"},
        "csrftoken": {"name": "Django", "type": "framework"},
        "laravel_session": {"name": "Laravel", "type": "framework"},
        "express_sid": {"name": "Express.js", "type": "framework"},
        "connect.sid": {"name": "Connect/Express", "type": "framework"},
        "ASP.NET_SessionId": {"name": "ASP.NET", "type": "framework"},
        "__cfduid": {"name": "Cloudflare", "type": "cdn"},
        "__cflb": {"name": "Cloudflare", "type": "cdn"},
    }

    async def scan(self, target: ScanTarget) -> ScanResult:
        result = self.create_result()
        fingerprints = []

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.timeout_seconds,
                verify=False,
                headers={"User-Agent": "KindMelody-Security-Scanner/1.0"},
            ) as client:
                response = await client.get(target.url)
                headers = dict(response.headers)
                cookies = response.cookies
                body = response.text[:30000]

                fp_from_server = self._fingerprint_server(headers)
                if fp_from_server:
                    fingerprints.extend(fp_from_server)

                fp_from_headers = self._fingerprint_headers(headers)
                if fp_from_headers:
                    fingerprints.extend(fp_from_headers)

                fp_from_cookies = self._fingerprint_cookies(cookies)
                if fp_from_cookies:
                    fingerprints.extend(fp_from_cookies)

                fp_from_body = self._fingerprint_body(body)
                if fp_from_body:
                    fingerprints.extend(fp_from_body)

                result.raw_data["fingerprints"] = fingerprints
                result.raw_data["all_headers"] = headers

                self._assess_information_disclosure(headers, fingerprints, result)

        except Exception as e:
            logger.warning("fingerprint_scan_error", error=str(e))

        return result

    def _fingerprint_server(self, headers: dict) -> list[dict]:
        found = []
        server = headers.get("server", "")
        if not server:
            return found

        for pattern, info in self.SERVER_PATTERNS.items():
            match = re.search(pattern, server, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else None
                found.append({
                    "source": "Server header",
                    "value": server,
                    **info,
                    "version": version,
                })
                break

        return found

    def _fingerprint_headers(self, headers: dict) -> list[dict]:
        found = []
        h_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, info in self.HEADER_FINGERPRINTS.items():
            if header_name in h_lower:
                found.append({
                    "source": f"{header_name} header",
                    "value": h_lower[header_name][:100],
                    **info,
                })

        return found

    def _fingerprint_cookies(self, cookies) -> list[dict]:
        found = []
        for cookie_name in cookies.keys():
            for pattern, info in self.COOKIE_FINGERPRINTS.items():
                if pattern.lower() in cookie_name.lower():
                    found.append({
                        "source": f"Cookie: {cookie_name}",
                        "value": "",
                        **info,
                    })
                    break

        set_cookie = ""
        if hasattr(cookies, 'jar'):
            for cookie in cookies.jar:
                set_cookie += cookie.name + "="

        return found

    def _fingerprint_body(self, body: str) -> list[dict]:
        found = []
        body_lower = body.lower()

        body_signatures = [
            ("wp-content", "WordPress", "cms"),
            ("drupal", "Drupal", "cms"),
            ("joomla", "Joomla", "cms"),
            ("django-admin", "Django", "framework"),
            ("rails-default-error-page", "Ruby on Rails", "framework"),
            ("laravel", "Laravel", "framework"),
            ("next.js", "Next.js", "framework"),
            ("react", "React", "framework"),
            ("vue.js", "Vue.js", "framework"),
            ("angular", "Angular", "framework"),
        ]

        for sig, name, tech_type in body_signatures:
            if sig in body_lower:
                found.append({
                    "source": "HTML body",
                    "value": sig,
                    "name": name,
                    "type": tech_type,
                })

        return found

    def _assess_information_disclosure(self, headers: dict, fingerprints: list, result: ScanResult) -> None:
        sensitive_headers = [
            "x-powered-by",
            "server",
            "x-aspnet-version",
            "x-aspnetmvc-version",
            "x-generator",
        ]

        disclosed = []
        for h in sensitive_headers:
            if h in headers:
                disclosed.append(f"{h}: {headers[h][:50]}")

        if len(disclosed) > 2:
            result.add_finding(
                title="Excessive information disclosure in headers",
                description=f"{len(disclosed)} informative headers are exposed, revealing technology stack details to potential attackers.",
                severity="low",
                confidence="high",
                recommendation="Remove or obfuscate headers like X-Powered-By, X-Generator, and detailed Server headers.",
                score_impact=-2.0,
                evidence={"disclosed_headers": disclosed},
            )

        has_server_header = "server" in headers
        if not has_server_header:
            result.raw_data["server_header_hidden"] = True
