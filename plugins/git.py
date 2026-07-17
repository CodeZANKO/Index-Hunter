"""Git detector plugin - flags exposed .git directories / objects."""
import urllib.parse


def run(finding, data):
    path = finding.get("path", "").lower()
    if "/.git/" in path or path.endswith("/.git") or path.endswith("head") and "/.git/" in path:
        finding["framework"] = "Git"
        if finding.get("severity") not in ("critical", "high"):
            finding["severity"] = "high"
