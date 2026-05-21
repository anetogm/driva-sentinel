import re

import httpx

from app.core.logging import get_logger
from app.scanner_engine.base import BaseScanner, ScanResult, ScanTarget

logger = get_logger("tech_scanner")


class TechScanner(BaseScanner):
    name = "tech"
    category = "tech"
    timeout_seconds = 30

    TECH_SIGNATURES = {
        "WordPress": {
            "headers": [("x-powered-by", "wordpress")],
            "body": ["/wp-content/", "/wp-includes/", "wp-json", "generator" content="wordpress"],
            "meta": ["wordpress"],
        },
        "Drupal": {
            "headers": [],
            "body": ["/sites/default/", "drupal", "generator" content="drupal"],
            "meta": ["drupal"],
        },
        "Joomla": {
            "headers": [],
            "body": ["/media/jui/", "joomla", "generator" content="joomla"],
            "meta": ["joomla"],
        },
        "React": {
            "headers": [],
            "body": ["reactroot", "data-reactroot", "__react_internal"],
            "meta": [],
        },
        "Next.js": {
            "headers": [("x-powered-by", "next.js")],
            "body": ["__next", "_next/static", "next.js"],
            "meta": [],
        },
        "Vue.js": {
            "headers": [],
            "body": ["vue", "data-v-", "__vue__"],
            "meta": [],
        },
        "Angular": {
            "headers": [],
            "body": ["ng-app", "ng-controller", "angular"],
            "meta": [],
        },
        "jQuery": {
            "headers": [],
            "body": ["jquery", "/jquery", "jquery.min.js"],
            "meta": [],
        },
        "Bootstrap": {
            "headers": [],
            "body": ["bootstrap", "/bootstrap", "bootstrap.min.css"],
            "meta": [],
        },
        "nginx": {
            "headers": [("server", "nginx")],
            "body": [],
            "meta": [],
        },
        "Apache": {
            "headers": [("server", "apache")],
            "body": [],
            "meta": [],
        },
        "Cloudflare": {
            "headers": [
                ("server", "cloudflare"),
                ("cf-ray", ""),
                ("cf-cache-status", ""),
            ],
            "body": [],
            "meta": [],
        },
        "AWS": {
            "headers": [("x-amz-request-id", ""), ("x-amz-id-2", "")],
            "body": [],
            "meta": [],
        },
        "Akamai": {
            "headers": [("x-akamai-transformed", ""), ("x-akamai-request-id", "")],
            "body": [],
            "meta": [],
        },
        "Fastly": {
            "headers": [("x-fastly", ""), ("x-served-by", "cache-")],
            "body": [],
            "meta": [],
        },
        "PHP": {
            "headers": [("x-powered-by", "php")],
            "body": [".php", "php"],
            "meta": [],
        },
        "Python": {
            "headers": [("server", "python"), ("x-powered-by", "python")],
            "body": [],
            "meta": [],
        },
        "Express.js": {
            "headers": [("x-powered-by", "express")],
            "body": [],
            "meta": [],
        },
        "Django": {
            "headers": [("server", "wsGIServer"), ("x-frame-options", "sameorigin")],
            "body": ["csrfmiddlewaretoken", "django"],
            "meta": [],
        },
        "Ruby on Rails": {
            "headers": [("x-runtime", ""), ("x-request-id", "")],
            "body": ["csrf-param", "authenticity_token"],
            "meta": [],
        },
        "Laravel": {
            "headers": [],
            "body": ["laravel_session", "csrf-token"],
            "meta": [],
        },
        "ModSecurity": {
            "headers": [("x-mod-security", "")],
            "body": [],
            "meta": [],
        },
        "Wordfence": {
            "headers": [],
            "body": ["wordfence", "wf-scan"],
            "meta": [],
        },
        "Sucuri": {
            "headers": [("x-sucuri-id", "")],
            "body": [],
            "meta": [],
        },
        "Imperva": {
            "headers": [("x-iinfo", "")],
            "body": [],
            "meta": [],
        },
    }

    async def scan(self, target: ScanTarget) -> ScanResult:
        result = self.create_result()
        detected = []

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.timeout_seconds,
                verify=False,
                headers={"User-Agent": "KindMelody-Security-Scanner/1.0"},
            ) as client:
                response = await client.get(target.url)
                headers = dict(response.headers)
                body = response.text[:50000].lower()

                for tech_name, signatures in self.TECH_SIGNATURES.items():
                    detected_tech = self._detect_technology(tech_name, signatures, headers, body)
                    if detected_tech:
                        detected.append(detected_tech)

                result.raw_data["detected_technologies"] = detected
                result.raw_data["headers"] = headers

                self._check_outdated_versions(detected, result)
                self._assess_attack_surface(detected, result)

        except Exception as e:
            logger.warning("tech_scan_error", error=str(e))
            result.add_finding(
                title="Technology detection scan error",
                description=f"Could not complete technology detection: {str(e)}",
                severity="info",
                confidence="medium",
            )

        return result

    def _detect_technology(self, name: str, signatures: dict, headers: dict, body: str) -> dict | None:
        h_lower = {k.lower(): v.lower() for k, v in headers.items()}
        found = False
        evidence = []

        for header_key, header_value in signatures.get("headers", []):
            hk_lower = header_key.lower()
            if hk_lower in h_lower:
                if not header_value or header_value in h_lower[hk_lower]:
                    found = True
                    evidence.append(f"header:{header_key}={headers.get(header_key, '')}")

        for body_sig in signatures.get("body", []):
            if body_sig.lower() in body:
                found = True
                evidence.append(f"body:{body_sig}")

        if found:
            return {
                "name": name,
                "category": self._get_category(name),
                "confidence": "high" if len(evidence) > 1 else "medium",
                "evidence": evidence[:3],
            }
        return None

    def _get_category(self, tech_name: str) -> str:
        categories = {
            "WordPress": "CMS",
            "Drupal": "CMS",
            "Joomla": "CMS",
            "React": "Framework",
            "Next.js": "Framework",
            "Vue.js": "Framework",
            "Angular": "Framework",
            "jQuery": "Library",
            "Bootstrap": "Library",
            "nginx": "Web Server",
            "Apache": "Web Server",
            "Cloudflare": "CDN/WAF",
            "AWS": "Cloud",
            "Akamai": "CDN",
            "Fastly": "CDN",
            "PHP": "Language",
            "Python": "Language",
            "Express.js": "Framework",
            "Django": "Framework",
            "Ruby on Rails": "Framework",
            "Laravel": "Framework",
            "ModSecurity": "WAF",
            "Wordfence": "WAF",
            "Sucuri": "WAF",
            "Imperva": "WAF",
        }
        return categories.get(tech_name, "Other")

    def _check_outdated_versions(self, detected: list, result: ScanResult) -> None:
        for tech in detected:
            name = tech["name"]
            if name in ["jQuery", "Bootstrap", "WordPress", "Drupal", "Joomla"]:
                result.add_finding(
                    title=f"Potentially outdated {name} detected",
                    description=f"{name} was detected but its version could not be verified. Ensure you are running the latest version with security patches.",
                    severity="low",
                    confidence="medium",
                    recommendation=f"Verify {name} version and update to the latest stable release.",
                    score_impact=-1.0,
                    evidence={"technology": name},
                )

    def _assess_attack_surface(self, detected: list, result: ScanResult) -> None:
        cms_detected = [t for t in detected if t["category"] == "CMS"]
        if cms_detected:
            names = ", ".join(t["name"] for t in cms_detected)
            result.add_finding(
                title=f"CMS detected: {names}",
                description=f"The site uses {names} which is a common attack target. CMS platforms often have plugin vulnerabilities and require regular updates.",
                severity="info",
                confidence="high",
                recommendation="Keep the CMS and all plugins/themes updated. Remove unused plugins. Enable automatic security updates if available.",
                score_impact=-0.5,
                evidence={"cms": names},
            )

        waf_detected = [t for t in detected if t["category"] == "WAF"]
        if waf_detected:
            names = ", ".join(t["name"] for t in waf_detected)
            result.raw_data["waf_detected"] = names
        else:
            result.add_finding(
                title="No Web Application Firewall detected",
                description="No WAF was detected in front of the application. A WAF provides an additional layer of defense against common web attacks.",
                severity="low",
                confidence="medium",
                recommendation="Consider deploying a WAF (Cloudflare, AWS WAF, ModSecurity, etc.) for additional protection.",
                score_impact=-1.0,
            )
