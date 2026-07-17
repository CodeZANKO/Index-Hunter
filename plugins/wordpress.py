"""WordPress detector plugin.

Enrich a finding with framework = WordPress when the path indicates a
WordPress install. Plugins receive (finding, data) and may mutate `finding`.
"""
import urllib.parse


def run(finding, data):
    path = finding.get("path", "").lower()
    name = finding.get("filename", "").lower()
    if "wp-config" in path or "wp-config" in name or "wp-content" in path or "wp-includes" in path:
        finding["framework"] = "WordPress"
