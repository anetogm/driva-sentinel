import httpx

from app.core.logging import get_logger
from app.scanner_engine.base import BaseScanner, ScanResult, ScanTarget

logger = get_logger("web_scanner")


class WebScanner(BaseScanner):
    name = "web"
    category = "web"
    timeout_seconds = 30

    COMMON_PATHS = [
        ".git/HEAD",
        ".git/config",
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        ".htaccess",
        ".htpasswd",
        "config.php",
        "config.js",
        "wp-config.php",
        "backup.sql",
        "dump.sql",
        "database.sql",
        ".backup",
        ".bak",
        ".old",
        ".swp",
        "admin/",
        "administrator/",
        "wp-admin/",
        "phpmyadmin/",
        "phpinfo.php",
        "info.php",
        "test.php",
        "api/swagger.json",
        "swagger.json",
        "api/docs",
        ".DS_Store",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
    ]

    async def scan(self, target: ScanTarget) -> ScanResult:
        result = self.create_result()
        base = target.url.rstrip("/")

        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=self.timeout_seconds,
                verify=False,
                headers={
                    "User-Agent": "KindMelody-Security-Scanner/1.0",
                },
            ) as client:
                await self._check_exposed_paths(base, client, result)
                await self._check_robots_sitemap(base, client, result)
                await self._check_http_methods(base, client, result)
                await self._check_cors_misconfig(base, client, result)
                await self._check_clickjacking(base, client, result)
                await self._check_open_redirect(base, client, result)
                await self._check_error_leakage(base, client, result)

        except Exception as e:
            logger.warning("web_scan_error", error=str(e))
            result.add_finding(
                title="Web scan encountered an error",
                description=f"Error during web scan: {str(e)}",
                severity="info",
                confidence="medium",
            )

        return result

    async def _check_exposed_paths(self, base: str, client: httpx.AsyncClient, result: ScanResult) -> None:
        found_paths = []

        for path in self.COMMON_PATHS[:15]:
            try:
                url = f"{base}/{path}"
                response = await client.get(url)

                if response.status_code == 200:
                    content_length = len(response.text)
                    if content_length > 10:
                        found_paths.append({
                            "path": path,
                            "status": response.status_code,
                            "size": content_length,
                        })

                        if ".git/" in path:
                            result.add_finding(
                                title="Exposed Git repository",
                                description=f"The .git directory is accessible at /{path}. Attackers can download the entire source code history.",
                                severity="critical",
                                confidence="high",
                                recommendation="Block access to .git directories. In nginx: location ~ /\.git { deny all; }",
                                score_impact=-15.0,
                                evidence={"path": f"/{path}", "status": 200},
                            )
                        elif ".env" in path:
                            result.add_finding(
                                title="Exposed environment file",
                                description=f"An environment file (.env) is accessible at /{path}. This may contain secrets, API keys, and database credentials.",
                                severity="critical",
                                confidence="high",
                                recommendation="Remove .env files from the web root. Add them to .gitignore and server block rules.",
                                score_impact=-15.0,
                                evidence={"path": f"/{path}", "status": 200},
                            )
                        elif path.endswith(".sql") or ".backup" in path or path.endswith(".bak"):
                            result.add_finding(
                                title="Exposed backup or database file",
                                description=f"A backup/database file is accessible at /{path}. This may contain sensitive data.",
                                severity="high",
                                confidence="high",
                                recommendation="Remove backup files from the web server. Store backups in a secure location.",
                                score_impact=-10.0,
                                evidence={"path": f"/{path}", "status": 200},
                            )
                        elif "admin" in path.lower() or "phpmyadmin" in path.lower():
                            result.add_finding(
                                title="Admin panel exposed",
                                description=f"An administrative interface is accessible at /{path}. If not properly protected, this is a major security risk.",
                                severity="high",
                                confidence="high",
                                recommendation="Restrict admin panels by IP, use strong authentication, and consider VPN-only access.",
                                score_impact=-8.0,
                                evidence={"path": f"/{path}", "status": 200},
                            )
                        elif "swagger" in path.lower() or "api/docs" in path.lower():
                            result.add_finding(
                                title="API documentation exposed",
                                description=f"API documentation (Swagger) is publicly accessible at /{path}. This reveals API endpoints and schemas to attackers.",
                                severity="medium",
                                confidence="high",
                                recommendation="Restrict API docs to internal networks or authenticated users in production.",
                                score_impact=-3.0,
                                evidence={"path": f"/{path}", "status": 200},
                            )

            except Exception:
                continue

        result.raw_data["exposed_paths"] = found_paths

    async def _check_robots_sitemap(self, base: str, client: httpx.AsyncClient, result: ScanResult) -> None:
        for path in ["/robots.txt", "/sitemap.xml"]:
            try:
                response = await client.get(f"{base}{path}")
                if response.status_code == 200:
                    content = response.text[:2000]
                    result.raw_data[path.strip("/")] = content

                    if path == "/robots.txt":
                        sensitive_paths = [
                            "admin", "backup", "config", "secret", "private",
                            "internal", "api", "debug", "test", "staging",
                        ]
                        leaks = []
                        for sp in sensitive_paths:
                            if sp in content.lower():
                                leaks.append(sp)
                        if leaks:
                            result.add_finding(
                                title="robots.txt reveals sensitive paths",
                                description=f"robots.txt references potentially sensitive paths: {', '.join(leaks)}. While intended to guide crawlers, this information helps attackers.",
                                severity="low",
                                confidence="medium",
                                recommendation="Remove sensitive paths from robots.txt. Use authentication and proper access controls instead.",
                                score_impact=-1.5,
                                evidence={"leaked_paths": leaks},
                            )
            except Exception:
                pass

    async def _check_http_methods(self, base: str, client: httpx.AsyncClient, result: ScanResult) -> None:
        methods = ["TRACE", "OPTIONS", "PUT", "DELETE", "PATCH"]
        enabled_methods = []

        for method in methods:
            try:
                response = await client.request(method, base)
                if response.status_code not in (405, 501, 403):
                    enabled_methods.append({"method": method, "status": response.status_code})
            except Exception:
                pass

        result.raw_data["http_methods"] = enabled_methods

        if any(m["method"] == "TRACE" for m in enabled_methods):
            result.add_finding(
                title="HTTP TRACE method enabled",
                description="The TRACE method is enabled. This can be exploited for Cross-Site Tracing (XST) attacks to bypass HttpOnly cookie protections.",
                severity="medium",
                confidence="high",
                recommendation="Disable TRACE method. In Apache: TraceEnable off. In nginx: add 'if ($request_method = TRACE) { return 405; }'",
                score_impact=-4.0,
            )

        dangerous = ["PUT", "DELETE", "PATCH"]
        found_dangerous = [m for m in enabled_methods if m["method"] in dangerous]
        if found_dangerous:
            result.add_finding(
                title="Potentially dangerous HTTP methods enabled",
                description=f"The following potentially dangerous HTTP methods are enabled: {', '.join(m['method'] for m in found_dangerous)}. These can be used to modify or delete resources.",
                severity="medium",
                confidence="medium",
                recommendation="Disable unnecessary HTTP methods. Only enable those required by your application.",
                score_impact=-3.0,
                evidence={"methods": found_dangerous},
            )

    async def _check_cors_misconfig(self, base: str, client: httpx.AsyncClient, result: ScanResult) -> None:
        try:
            headers = {
                "Origin": "https://evil.com",
            }
            response = await client.get(base, headers=headers)
            acao = response.headers.get("access-control-allow-origin")
            acac = response.headers.get("access-control-allow-credentials")

            if acao == "https://evil.com":
                if acac and acac.lower() == "true":
                    result.add_finding(
                        title="CORS reflects arbitrary origin with credentials",
                        description="The server reflects any Origin header and allows credentials. This is a critical vulnerability allowing attackers to make authenticated cross-origin requests.",
                        severity="critical",
                        confidence="high",
                        recommendation="Implement a strict whitelist of allowed origins. Never reflect arbitrary origins when credentials are allowed.",
                        score_impact=-15.0,
                        evidence={"origin": "https://evil.com", "acao": acao, "acac": acac},
                    )
                else:
                    result.add_finding(
                        title="CORS reflects arbitrary origin",
                        description="The server reflects any Origin header without credentials. This may allow unauthorized cross-origin access to public data.",
                        severity="medium",
                        confidence="high",
                        recommendation="Implement a strict whitelist of allowed origins.",
                        score_impact=-4.0,
                        evidence={"origin": "https://evil.com", "acao": acao},
                    )
            elif acao == "*" and acac and acac.lower() == "true":
                result.add_finding(
                    title="CORS wildcard with credentials is invalid",
                    description="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is an invalid configuration that browsers reject.",
                    severity="low",
                    confidence="high",
                    recommendation="Remove wildcard or credentials, and implement proper origin validation.",
                    score_impact=-1.0,
                )

            result.raw_data["cors_test"] = {
                "origin_tested": "https://evil.com",
                "acao": acao,
                "acac": acac,
            }
        except Exception:
            pass

    async def _check_clickjacking(self, base: str, client: httpx.AsyncClient, result: ScanResult) -> None:
        try:
            response = await client.get(base)
            xfo = response.headers.get("x-frame-options")
            csp = response.headers.get("content-security-policy", "")

            if not xfo and "frame-ancestors" not in csp.lower():
                pass

            result.raw_data["clickjacking_test"] = {
                "x_frame_options": xfo,
                "csp_frame_ancestors": "frame-ancestors" in csp.lower(),
            }
        except Exception:
            pass

    async def _check_open_redirect(self, base: str, client: httpx.AsyncClient, result: ScanResult) -> None:
        payloads = [
            "?redirect=https://evil.com",
            "?next=https://evil.com",
            "?url=https://evil.com",
            "?return=https://evil.com",
            "?redirect_uri=https://evil.com",
            "?callback=https://evil.com",
        ]

        found_redirects = []
        for payload in payloads[:3]:
            try:
                test_url = f"{base}/{payload}"
                response = await client.get(test_url, follow_redirects=False)
                if response.status_code in (301, 302, 307, 308):
                    location = response.headers.get("location", "")
                    if "evil.com" in location:
                        found_redirects.append({"payload": payload, "location": location})
            except Exception:
                pass

        if found_redirects:
            result.add_finding(
                title="Open redirect vulnerability detected",
                description="The application appears to redirect to arbitrary URLs provided in query parameters. This can be used in phishing attacks.",
                severity="high",
                confidence="medium",
                recommendation="Validate and whitelist redirect destinations. Use internal mapping instead of direct URL parameters.",
                score_impact=-8.0,
                evidence={"redirects": found_redirects},
            )

    async def _check_error_leakage(self, base: str, client: httpx.AsyncClient, result: ScanResult) -> None:
        try:
            response = await client.get(f"{base}/this-should-not-exist-404-test")
            if response.status_code == 404:
                body = response.text.lower()
                leak_indicators = [
                    ("stack trace", "Stack trace exposed"),
                    ("traceback", "Python traceback exposed"),
                    ("exception", "Exception details exposed"),
                    ("laravel", "Laravel framework error page"),
                    ("django", "Django debug page"),
                    ("symfony", "Symfony error page"),
                    ("apache", "Apache server version leaked in error"),
                    ("nginx", "Nginx version leaked in error"),
                    ("php version", "PHP version leaked"),
                    ("sql syntax", "SQL syntax error exposed"),
                    ("mysql", "MySQL error details"),
                    ("postgresql", "PostgreSQL error details"),
                    ("mongodb", "MongoDB error details"),
                ]

                for indicator, title in leak_indicators:
                    if indicator in body[:5000]:
                        result.add_finding(
                            title=title,
                            description=f"Error pages contain detailed information about '{indicator}'. This helps attackers fingerprint the technology stack.",
                            severity="medium",
                            confidence="medium",
                            recommendation="Configure custom error pages that do not leak stack traces, framework names, or version information.",
                            score_impact=-3.0,
                        )
                        break

            result.raw_data["error_page_test"] = {
                "status": response.status_code,
                "length": len(response.text),
            }
        except Exception:
            pass
