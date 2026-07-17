"""Laravel detector plugin."""
import urllib.parse


def run(finding, data):
    path = finding.get("path", "").lower()
    name = finding.get("filename", "").lower()
    if name == "artisan" or "vendor/laravel" in path or "storage/logs" in path or path.endswith("/.env"):
        finding["framework"] = "Laravel"
    elif name == ".env" and finding.get("category") == "CONFIG":
        # .env can belong to many frameworks; only tag if Laravel signals present elsewhere
        pass
