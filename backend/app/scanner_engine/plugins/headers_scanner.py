import httpx

from app.core.logging import get_logger
from app.scanner_engine.base import BaseScanner, ScanResult, ScanTarget

logger = get_logger("headers_scanner")


class HeadersScanner(BaseScanner):
    name = "headers"
    category = "headers"
    timeout_seconds = 30

    async def scan(self, target: ScanTarget) -> ScanResult:
        result = self.create_result()

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.timeout_seconds,
                verify=False,
            ) as client:
                response = await client.get(target.url)
                headers = dict(response.headers)
                cookies = response.cookies
        except Exception as e:
            logger.warning("headers_fetch_error", error=str(e))
            result.add_finding(
                title="Could not fetch target for header analysis",
                description=f"Failed to retrieve headers: {str(e)}",
                severity="info",
                confidence="high",
            )
            return result

        h = {k.lower(): v for k, v in headers.items()}

        self._check_csp(h, result)
        self._check_hsts(h, result)
        self._check_x_frame_options(h, result)
        self._check_x_content_type_options(h, result)
        self._check_referrer_policy(h, result)
        self._check_permissions_policy(h, result)
        self._check_cors(h, result)
        self._check_cookies(cookies, headers, result)
        self._check_cache_control(h, result)
        self._check_server_leakage(h, result)
        self._check_x_xss_protection(h, result)

        result.raw_data = {"headers": headers}
        return result

    def _check_csp(self, h: dict, result: ScanResult) -> None:
        csp = h.get("content-security-policy")
        if not csp:
            result.add_finding(
                title="Missing Content-Security-Policy header",
                description="The Content-Security-Policy header is missing. CSP helps prevent XSS and data injection attacks by specifying allowed content sources.",
                severity="high",
                confidence="high",
                recommendation="Add a Content-Security-Policy header with appropriate directives. Example: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
                score_impact=-10.0,
            )
        else:
            if "unsafe-inline" in csp and "'nonce-" not in csp and "'sha256-" not in csp:
                result.add_finding(
                    title="CSP allows unsafe-inline without nonce/hash",
                    description="The CSP allows 'unsafe-inline' for scripts or styles without using nonces or hashes, weakening XSS protection.",
                    severity="medium",
                    confidence="high",
                    recommendation="Replace 'unsafe-inline' with nonce or hash-based approaches, or use strict-dynamic.",
                    score_impact=-3.0,
                )
            if "*" in csp:
                result.add_finding(
                    title="CSP uses wildcard sources",
                    description="The CSP contains wildcard (*) sources which allow content from any origin, defeating the purpose of CSP.",
                    severity="medium",
                    confidence="high",
                    recommendation="Replace wildcard sources with specific trusted domains.",
                    score_impact=-3.0,
                )
            if "default-src" not in csp.lower():
                result.add_finding(
                    title="CSP missing default-src directive",
                    description="The CSP does not include a default-src directive, meaning some resource types may not be restricted.",
                    severity="low",
                    confidence="high",
                    recommendation="Add default-src 'self' as a baseline directive.",
                    score_impact=-1.0,
                )

    def _check_hsts(self, h: dict, result: ScanResult) -> None:
        hsts = h.get("strict-transport-security")
        if not hsts:
            result.add_finding(
                title="Missing Strict-Transport-Security header",
                description="HSTS is missing. Without HSTS, the site may be vulnerable to SSL stripping attacks where an attacker forces the connection to downgrade to HTTP.",
                severity="high",
                confidence="high",
                recommendation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                score_impact=-10.0,
            )
        else:
            if "max-age" in hsts:
                try:
                    age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                    if age < 2592000:
                        result.add_finding(
                            title="HSTS max-age is too short",
                            description=f"HSTS max-age is {age} seconds (less than 30 days). Browsers may forget the HSTS policy quickly.",
                            severity="low",
                            confidence="high",
                            recommendation="Set max-age to at least 31536000 (1 year).",
                            score_impact=-1.0,
                        )
                except (IndexError, ValueError):
                    pass
            if "includesubdomains" not in hsts.lower():
                result.add_finding(
                    title="HSTS missing includeSubDomains",
                    description="HSTS is not applied to subdomains, leaving them vulnerable to SSL stripping.",
                    severity="medium",
                    confidence="high",
                    recommendation="Add includeSubDomains directive.",
                    score_impact=-2.0,
                )

    def _check_x_frame_options(self, h: dict, result: ScanResult) -> None:
        xfo = h.get("x-frame-options")
        csp = h.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp.lower():
            result.add_finding(
                title="Missing clickjacking protection",
                description="Neither X-Frame-Options nor CSP frame-ancestors is set. The site may be embedded in malicious iframes (clickjacking attacks).",
                severity="high",
                confidence="high",
                recommendation="Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors directive.",
                score_impact=-8.0,
            )
        elif xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
            result.add_finding(
                title="Invalid X-Frame-Options value",
                description=f"X-Frame-Options has an invalid value: '{xfo}'. Only DENY or SAMEORIGIN are valid.",
                severity="medium",
                confidence="high",
                recommendation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                score_impact=-3.0,
            )

    def _check_x_content_type_options(self, h: dict, result: ScanResult) -> None:
        xcto = h.get("x-content-type-options")
        if not xcto:
            result.add_finding(
                title="Missing X-Content-Type-Options header",
                description="Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses and render them as different content types, leading to XSS.",
                severity="medium",
                confidence="high",
                recommendation="Add X-Content-Type-Options: nosniff",
                score_impact=-4.0,
            )
        elif xcto.lower() != "nosniff":
            result.add_finding(
                title="Invalid X-Content-Type-Options value",
                description=f"X-Content-Type-Options has value '{xcto}' instead of 'nosniff'.",
                severity="low",
                confidence="high",
                recommendation="Set X-Content-Type-Options to nosniff.",
                score_impact=-1.0,
            )

    def _check_referrer_policy(self, h: dict, result: ScanResult) -> None:
        rp = h.get("referrer-policy")
        if not rp:
            result.add_finding(
                title="Missing Referrer-Policy header",
                description="No Referrer-Policy is set. Sensitive URL information may leak to third parties through the Referer header.",
                severity="low",
                confidence="medium",
                recommendation="Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
                score_impact=-2.0,
            )
        elif rp.lower() in ("unsafe-url", "origin-when-cross-origin"):
            result.add_finding(
                title="Weak Referrer-Policy value",
                description=f"Referrer-Policy is set to '{rp}' which may leak sensitive URL data to third parties.",
                severity="low",
                confidence="high",
                recommendation="Use strict-origin-when-cross-origin or no-referrer for better privacy.",
                score_impact=-1.0,
            )

    def _check_permissions_policy(self, h: dict, result: ScanResult) -> None:
        pp = h.get("permissions-policy") or h.get("feature-policy")
        if not pp:
            result.add_finding(
                title="Missing Permissions-Policy header",
                description="No Permissions-Policy is set. Browser features like camera, microphone, geolocation may be accessible to embedded content.",
                severity="low",
                confidence="medium",
                recommendation="Add Permissions-Policy with restrictive defaults. Example: camera=(), microphone=(), geolocation=()",
                score_impact=-1.5,
            )

    def _check_cors(self, h: dict, result: ScanResult) -> None:
        acao = h.get("access-control-allow-origin")
        if acao == "*":
            result.add_finding(
                title="CORS allows all origins",
                description="Access-Control-Allow-Origin is set to *, allowing any website to make cross-origin requests. This may expose sensitive data.",
                severity="medium",
                confidence="high",
                recommendation="Restrict CORS to specific trusted origins instead of using wildcard.",
                score_impact=-4.0,
            )

    def _check_cookies(self, cookies, headers, result: ScanResult) -> None:
        set_cookie = headers.get("set-cookie", "")
        if not set_cookie:
            return

        sc_lower = set_cookie.lower()
        if "secure" not in sc_lower:
            result.add_finding(
                title="Cookie missing Secure flag",
                description="A Set-Cookie header is missing the Secure flag, meaning the cookie may be transmitted over unencrypted connections.",
                severity="high",
                confidence="medium",
                recommendation="Add Secure flag to all cookies: Set-Cookie: name=value; Secure",
                score_impact=-6.0,
            )
        if "httponly" not in sc_lower:
            result.add_finding(
                title="Cookie missing HttpOnly flag",
                description="A Set-Cookie header is missing the HttpOnly flag, making the cookie accessible to JavaScript and vulnerable to XSS cookie theft.",
                severity="high",
                confidence="medium",
                recommendation="Add HttpOnly flag to all cookies: Set-Cookie: name=value; HttpOnly",
                score_impact=-6.0,
            )
        if "samesite" not in sc_lower:
            result.add_finding(
                title="Cookie missing SameSite attribute",
                description="A Set-Cookie header is missing the SameSite attribute, making the cookie vulnerable to CSRF attacks.",
                severity="medium",
                confidence="medium",
                recommendation="Add SameSite=Strict or SameSite=Lax to all cookies.",
                score_impact=-3.0,
            )
        elif "samesite=none" in sc_lower and "secure" not in sc_lower:
            result.add_finding(
                title="SameSite=None cookie missing Secure flag",
                description="A cookie with SameSite=None requires the Secure flag to be set. This combination is invalid and browsers will reject it.",
                severity="medium",
                confidence="high",
                recommendation="Add Secure flag when using SameSite=None.",
                score_impact=-3.0,
            )

    def _check_cache_control(self, h: dict, result: ScanResult) -> None:
        cc = h.get("cache-control", "").lower()
        if not cc and h.get("pragma") != "no-cache":
            result.add_finding(
                title="Missing Cache-Control header",
                description="No Cache-Control header is set. Sensitive responses may be cached by browsers or intermediate proxies.",
                severity="low",
                confidence="medium",
                recommendation="Add Cache-Control: no-store, no-cache, must-revalidate for sensitive pages.",
                score_impact=-1.5,
            )

    def _check_server_leakage(self, h: dict, result: ScanResult) -> None:
        server = h.get("server")
        x_powered = h.get("x-powered-by")
        via = h.get("via")

        if server:
            result.add_finding(
                title="Server header leaks technology information",
                description=f"The Server header reveals: '{server}'. This information helps attackers identify specific vulnerabilities.",
                severity="low",
                confidence="high",
                recommendation="Remove or obfuscate the Server header. In nginx: server_tokens off; In Apache: ServerTokens Prod",
                score_impact=-1.0,
                evidence={"header_value": server},
            )
        if x_powered:
            result.add_finding(
                title="X-Powered-By header leaks framework information",
                description=f"X-Powered-By reveals: '{x_powered}'. Attackers can use this to target framework-specific vulnerabilities.",
                severity="low",
                confidence="high",
                recommendation="Remove X-Powered-By header entirely.",
                score_impact=-1.0,
                evidence={"header_value": x_powered},
            )
        if via:
            result.add_finding(
                title="Via header reveals proxy information",
                description=f"Via header reveals: '{via}'. This exposes proxy/proxy chain information.",
                severity="info",
                confidence="high",
                recommendation="Consider removing the Via header to reduce information leakage.",
                score_impact=-0.5,
                evidence={"header_value": via},
            )

    def _check_x_xss_protection(self, h: dict, result: ScanResult) -> None:
        xxp = h.get("x-xss-protection")
        if xxp and xxp == "0":
            result.add_finding(
                title="X-XSS-Protection disabled",
                description="X-XSS-Protection is explicitly disabled (value 0). While modern browsers rely on CSP for XSS protection, this should be intentional.",
                severity="info",
                confidence="medium",
                recommendation="If CSP is properly configured, this is acceptable. Otherwise, consider enabling it.",
                score_impact=-0.5,
            )
