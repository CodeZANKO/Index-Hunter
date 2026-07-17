"""Docker detector plugin - flags Dockerfiles / compose files."""
import urllib.parse


def run(finding, data):
    name = finding.get("filename", "").lower()
    if name in ("dockerfile", "docker-compose.yml", "docker-compose.yaml"):
        finding["framework"] = "Docker"
        if finding.get("severity") not in ("critical", "high"):
            finding["severity"] = "medium"
