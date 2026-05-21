import httpx

from app.core.logging import get_logger
from app.scanner_engine.base import BaseScanner, ScanResult, ScanTarget

logger = get_logger("exposure_scanner")


class ExposureScanner(BaseScanner):
    name = "exposure"
    category = "exposure"
    timeout_seconds = 30

    SENSITIVE_PATHS = [
        (".well-known/security.txt", "security.txt"),
        ("security.txt", "security.txt root"),
        (".well-known/openid-configuration", "OpenID configuration"),
        (".well-known/ai-plugin.json", "AI plugin manifest"),
        ("graphql", "GraphQL endpoint"),
        ("graphiql", "GraphiQL interface"),
        (".vscode/settings.json", "VS Code settings"),
        ("package.json", "package.json"),
        ("composer.json", "composer.json"),
        ("requirements.txt", "requirements.txt"),
        ("Dockerfile", "Dockerfile"),
        ("docker-compose.yml", "docker-compose.yml"),
        (".dockerignore", ".dockerignore"),
        ("README.md", "README"),
        ("CHANGELOG.md", "Changelog"),
        ("LICENSE", "License"),
        (".github/workflows/ci.yml", "GitHub Actions workflow"),
        ("terraform.tfstate", "Terraform state"),
        ("server-status", "Apache server status"),
        ("server-info", "Apache server info"),
        ("actuator/health", "Spring Boot actuator"),
        ("actuator/env", "Spring Boot actuator env"),
        ("actuator/metrics", "Spring Boot actuator metrics"),
        ("actuator/dump", "Spring Boot actuator dump"),
        ("trace.axd", "ASP.NET trace"),
        ("elmah.axd", "ELMAH error log"),
        ("debug/console", "Debug console"),
        ("console", "Application console"),
    ]

    async def scan(self, target: ScanTarget) -> ScanResult:
        result = self.create_result()
        base = target.url.rstrip("/")

        try:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=self.timeout_seconds,
                verify=False,
                headers={"User-Agent": "KindMelody-Security-Scanner/1.0"},
            ) as client:
                for path, desc in self.SENSITIVE_PATHS[:15]:
                    try:
                        url = f"{base}/{path}"
                        response = await client.get(url)

                        if response.status_code == 200:
                            self._process_finding(path, desc, response, result)
                        elif response.status_code == 401 or response.status_code == 403:
                            if "actuator" in path:
                                result.add_finding(
                                    title=f"{desc} requires authentication",
                                    description=f"The {desc} endpoint exists but is protected. Verify that authentication is strong.",
                                    severity="info",
                                    confidence="medium",
                                    recommendation="Ensure actuator endpoints are not exposed publicly and require strong authentication.",
                                    score_impact=-0.5,
                                )
                    except Exception:
                        continue

                await self._check_directory_listing(base, client, result)

        except Exception as e:
            logger.warning("exposure_scan_error", error=str(e))

        return result

    def _process_finding(self, path: str, desc: str, response: httpx.Response, result: ScanResult) -> None:
        content = response.text[:2000]
        evidence = {"path": f"/{path}", "status": 200, "size": len(response.text)}

        if desc == "Terraform state":
            result.add_finding(
                title="Terraform state file exposed",
                description="A terraform.tfstate file is publicly accessible. This may contain cloud provider credentials, resource IDs, and other sensitive infrastructure data.",
                severity="critical",
                confidence="high",
                recommendation="Remove terraform.tfstate from the web server. Use remote state with encryption and access controls.",
                score_impact=-15.0,
                evidence=evidence,
            )
        elif "Spring Boot actuator" in desc:
            result.add_finding(
                title=f"{desc} endpoint exposed",
                description=f"The {desc} endpoint is publicly accessible. Spring Boot actuators can leak environment variables, configuration, and application internals.",
                severity="high",
                confidence="high",
                recommendation="Disable or restrict actuator endpoints. Set management.endpoints.web.exposure.include=health in application.properties.",
                score_impact=-10.0,
                evidence=evidence,
            )
        elif desc in ("GraphQL endpoint", "GraphiQL interface"):
            result.add_finding(
                title=f"{desc} exposed",
                description=f"The {desc} is publicly accessible without authentication. This may allow unauthorized data access or introspection attacks.",
                severity="high",
                confidence="high",
                recommendation="Disable introspection in production and require authentication for GraphQL endpoints.",
                score_impact=-8.0,
                evidence=evidence,
            )
        elif desc in ("ELMAH error log", "ASP.NET trace"):
            result.add_finding(
                title=f"{desc} exposed",
                description=f"The {desc} is publicly accessible, potentially exposing error details, stack traces, and application internals.",
                severity="high",
                confidence="high",
                recommendation="Remove or restrict access to diagnostic endpoints in production.",
                score_impact=-10.0,
                evidence=evidence,
            )
        elif desc in ("Debug console", "Application console"):
            result.add_finding(
                title=f"{desc} exposed",
                description=f"A {desc} is publicly accessible. This may allow arbitrary code execution on the server.",
                severity="critical",
                confidence="high",
                recommendation="Remove debug consoles from production deployments immediately.",
                score_impact=-15.0,
                evidence=evidence,
            )
        elif desc in ("Dockerfile", "docker-compose.yml", ".dockerignore"):
            result.add_finding(
                title="Docker files exposed",
                description=f"{desc} is publicly accessible, revealing container configuration and potentially secrets.",
                severity="medium",
                confidence="high",
                recommendation="Remove Docker files from the web root. They should not be served publicly.",
                score_impact=-3.0,
                evidence=evidence,
            )
        elif desc in ("package.json", "composer.json", "requirements.txt"):
            result.add_finding(
                title="Dependency manifest exposed",
                description=f"{desc} is publicly accessible, revealing exact dependency versions that may have known vulnerabilities.",
                severity="medium",
                confidence="high",
                recommendation="Remove dependency manifests from the web root. Use .gitignore and server configuration.",
                score_impact=-3.0,
                evidence=evidence,
            )
        elif "GitHub Actions" in desc:
            result.add_finding(
                title="CI/CD configuration exposed",
                description="GitHub Actions workflow files are publicly accessible, potentially revealing build processes and deployment pipelines.",
                severity="low",
                confidence="high",
                recommendation="Ensure CI/CD configurations do not contain secrets. Use GitHub Secrets for sensitive data.",
                score_impact=-1.5,
                evidence=evidence,
            )
        elif "security.txt" in desc:
            pass
        elif "OpenID configuration" in desc:
            result.add_finding(
                title="OpenID configuration exposed",
                description="OpenID Connect discovery endpoint is publicly accessible. This reveals authentication endpoints and supported flows.",
                severity="info",
                confidence="high",
                recommendation="This is expected for OIDC providers. Ensure endpoints are properly secured.",
                score_impact=0.0,
                evidence=evidence,
            )

    async def _check_directory_listing(self, base: str, client: httpx.AsyncClient, result: ScanResult) -> None:
        test_paths = ["/images/", "/css/", "/js/", "/assets/", "/uploads/"]
        found_listing = []

        for path in test_paths:
            try:
                response = await client.get(f"{base}{path}")
                if response.status_code == 200:
                    body = response.text.lower()
                    indicators = ["index of", "<title>index of", "directory listing", "parent directory", "[dir]"]
                    if any(ind in body for ind in indicators):
                        found_listing.append(path)
            except Exception:
                continue

        if found_listing:
            result.add_finding(
                title="Directory listing enabled",
                description=f"Directory listing is enabled on: {', '.join(found_listing)}. This exposes file structure and may reveal sensitive files.",
                severity="medium",
                confidence="high",
                recommendation="Disable directory listing in your web server configuration. In nginx: autoindex off; In Apache: Options -Indexes",
                score_impact=-3.0,
                evidence={"paths": found_listing},
            )
