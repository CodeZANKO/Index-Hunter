"""Secret classifiers, entropy analysis, and framework/cloud detection.

All detectors work on *text content* (decoded bytes) and return structured
results so the scanner and GUI can show exactly what was found.
"""
import re

# ---------------------------------------------------------------------------
# Exact secret classifiers
# Each: (label, severity, compiled regex, sample-mask-function?)
# severity is one of: critical, high, medium, low
# ---------------------------------------------------------------------------

def _mask(sample: str, keep=4) -> str:
    if len(sample) <= keep:
        return "*" * len(sample)
    return sample[:keep] + "*" * (len(sample) - keep)


_SECRET_SIGNATURES = [
    ("AWS Access Key", "critical",
     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", "critical",
     re.compile(r"(?i)(aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("Google API Key", "high",
     re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Google OAuth", "high",
     re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")),
    ("Stripe Secret Key", "critical",
     re.compile(r"sk_(live|test)_[0-9a-zA-Z]{16,}")),
    ("Stripe Restricted Key", "high",
     re.compile(r"rk_(live|test)_[0-9a-zA-Z]{16,}")),
    ("GitHub PAT", "critical",
     re.compile(r"ghp_[0-9A-Za-z]{36}")),
    ("GitHub Fine-grained PAT", "critical",
     re.compile(r"github_pat_[0-9A-Za-z_]{22,}")),
    ("GitHub OAuth", "high",
     re.compile(r"gho_[0-9A-Za-z]{36}")),
    ("GitLab PAT", "critical",
     re.compile(r"glpat-[0-9A-Za-z_\-]{20}")),
    ("GitLab Deploy Token", "high",
     re.compile(r"gldt-[0-9A-Za-z_\-]{20}")),
    ("JWT", "high",
     re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{10,}")),
    ("Private RSA Key", "critical",
     re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")),
    ("Private EC Key", "critical",
     re.compile(r"-----BEGIN EC PRIVATE KEY-----")),
    ("OpenSSH Private Key", "critical",
     re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    ("PGP Private Key", "high",
     re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")),
    ("MongoDB URI", "critical",
     re.compile(r"mongodb(\+srv)?://[^\s:@/]+:[^\s:@/]+@[^\s/]+")),
    ("MySQL Password (config)", "high",
     re.compile(r"(?i)(\$db_pass|\$password|password|db_password|mysql_password)\s*[:=]\s*['\"][^'\"]+['\"]")),
    ("Postgres URI", "critical",
     re.compile(r"postgres(ql)?://[^\s:@/]+:[^\s:@/]+@[^\s/]+")),
    ("Redis URI", "high",
     re.compile(r"redis://[^\s:@/]+:[^\s:@/]+@")),
    ("Slack Token", "high",
     re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Discord Bot Token", "high",
     re.compile(r"[MN][A-Za-z\d]{23,25}\.[\w\-]{6}\.[\w\-]{27,}")),
    ("Firebase Key", "high",
     re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Azure Storage Key", "high",
     re.compile(r"(?i)AccountKey=[A-Za-z0-9+/=]{40,}")),
    ("Azure SAS Token", "high",
     re.compile(r"(?i)sv=[0-9]{4}-[0-9]{2}-[0-9]{2}.*sig=[A-Za-z0-9%+/=]+")),
    ("Cloudflare API Token", "high",
     re.compile(r"(?i)cloudflare.*?(token|api_key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{30,}")),
    ("Cloudflare Global Key", "critical",
     re.compile(r"(?i)cloudflare.*?global.*?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{30,}")),
    ("OpenAI API Key", "critical",
     re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("Anthropic API Key", "critical",
     re.compile(r"sk-ant-[A-Za-z0-9\-]{20,}")),
    ("SendGrid Key", "high",
     re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}")),
    ("Twilio Key", "high",
     re.compile(r"(?i)twilio.*?(account_sid|auth_token)\s*[:=]\s*['\"]?[A-Za-z0-9]{20,}")),
    ("Generic API Key Assignment", "medium",
     re.compile(r"(?i)(api[_-]?key|apikey|client[_-]?secret|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]")),
    ("Database URL (generic)", "high",
     re.compile(r"(?i)(database_url|db_url|datasource\.url)\s*[:=]\s*['\"]?(?:mysql|postgres|mongodb|redis|oracle|mssql)://")),
    ("Terraform State", "high",
     re.compile(r'"serial":\s*\d+,\s*"lineage":\s*"[a-f0-9\-]+".*"resources":')),
    ("Kubernetes Config", "high",
     re.compile(r"apiVersion:\s*v1\s*.*kind:\s*(?:Secret|ConfigMap)")),
    ("Docker Compose", "medium",
     re.compile(r"version:\s*['\"]?\d+(?:\.\d+)?['\"]?\s*\n\s*services:")),
    (".git Directory", "medium",
     re.compile(r"\.git/(?:config|HEAD|index|refs/|objects/|logs/)")),
    (".svn Directory", "medium",
     re.compile(r"\.svn/(?:entries|wc\.db|pristine/)")),
    (".DS_Store", "low",
     re.compile(r"\.DS_Store")),
    ("Thumbs.db", "low",
     re.compile(r"Thumbs\.db")),
]


def scan_secrets(text: str):
    """Return list of dicts: {label, severity, sample(masked), match}."""
    results = []
    seen = set()
    for label, severity, rx in _SECRET_SIGNATURES:
        for m in rx.finditer(text):
            raw = m.group(0)
            # de-dupe identical masked samples per label
            key = (label, _mask(raw))
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "label": label,
                "severity": severity,
                "sample": _mask(raw),
                "match": raw if len(raw) <= 80 else raw[:80] + "...",
            })
    return results


# ---------------------------------------------------------------------------
# Entropy analysis
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    import math
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


# candidate high-entropy strings: long alphanumeric tokens
_CANDIDATE_RE = re.compile(r"[A-Za-z0-9_\-+/=]{16,}")


def scan_entropy(text: str, min_len: int = 20, threshold: float = 4.0, limit: int = 50):
    """Find high-entropy printable strings that regexes miss."""
    hits = []
    for tok in _CANDIDATE_RE.finditer(text):
        s = tok.group(0)
        if len(s) < min_len:
            continue
        # skip obviously structured things like jwt segments (already caught)
        score = shannon_entropy(s.encode("utf-8", "ignore"))
        if score >= threshold:
            hits.append({
                "string": s[:64] + ("..." if len(s) > 64 else ""),
                "length": len(s),
                "score": round(score, 2),
            })
            if len(hits) >= limit:
                break
    return hits


# ---------------------------------------------------------------------------
# Magic-byte / real file type detection
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"BM", "BMP image"),
    (b"\x00\x00\x01\x00", "ICO image"),
    (b"OggS", "OGG media"),
    (b"\x25\x21\x50\x53", "PostScript"),
    (b"ID3", "MP3 audio"),
    (b"\xfa\xbf\x00", "Mach-O binary"),
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "PE/EXE binary"),
    (b"SQLite", "SQLite database"),
    # Additional signatures
    (b"\x50\x4b\x07\x08", "ZIP archive (spanned)"),
    (b"\xfd7zXZ", "XZ archive"),
    (b"\x42\x5a\x68", "BZIP2 archive"),
    (b"\x28\xb5\x2f\xfd", "ZSTD archive"),
    (b"\x04\x22\x4d\x18", "LZ4 archive"),
    (b"\x1f\x9d", "LZH archive"),
    (b"\x75\x73\x74\x61\x72", "TAR archive (ustar)"),
    (b"SQLite format", "SQLite database"),
    (b"<?xml", "XML text"),
    (b"#!/bin/", "Shell script"),
    (b"#!/usr/bin/", "Script"),
    (b"{", "JSON/YAML text"),
]


def detect_magic(head: bytes):
    """Return detected type string from first bytes, or 'unknown'."""
    if not head:
        return "empty"
    for sig, name in MAGIC_SIGNATURES:
        if head.startswith(sig):
            return name
    # TAR: "ustar" at offset 257
    if len(head) >= 263 and head[257:263] == b"ustar":
        return "TAR archive"
    # text heuristics
    try:
        chunk = head.decode("utf-8")
        if chunk.lstrip().startswith("<?xml"):
            return "XML text"
        if chunk.lstrip().startswith(("<!DOCTYPE html", "<html")):
            return "HTML text"
        if chunk.lstrip().startswith("{") or chunk.lstrip().startswith("["):
            return "JSON text"
    except UnicodeDecodeError:
        pass
    return "unknown/binary"


# Map common extensions to the type we *expect* (for mismatch detection)
EXPECTED_TYPE = {
    ".png": "PNG image", ".jpg": "JPEG image", ".jpeg": "JPEG image",
    ".gif": "GIF image", ".pdf": "PDF document", ".zip": "ZIP archive",
    ".gz": "GZIP archive", ".rar": "RAR archive", ".7z": "7-Zip archive",
    ".tar": "TAR archive", ".sqlite": "SQLite database", ".db": "SQLite database",
    ".exe": "PE/EXE binary", ".dll": "PE/EXE binary", ".so": "ELF binary",
    ".xml": "XML text", ".html": "HTML text", ".json": "JSON text",
    ".xz": "XZ archive", ".bz2": "BZIP2 archive", ".zst": "ZSTD archive",
    ".lz4": "LZ4 archive", ".lzh": "LZH archive",
    ".webp": "WEBP image", ".avif": "AVIF image", ".tiff": "TIFF image",
    ".tif": "TIFF image", ".ico": "ICO image", ".svg": "SVG text",
    ".mp3": "MP3 audio", ".mp4": "MP4 video", ".mov": "QuickTime video",
    ".avi": "AVI video", ".mkv": "Matroska video", ".webm": "WebM video",
    ".flac": "FLAC audio", ".wav": "WAV audio", ".ogg": "OGG media",
    ".doc": "MS Word document", ".docx": "MS Word document",
    ".xls": "MS Excel document", ".xlsx": "MS Excel document",
    ".ppt": "MS PowerPoint document", ".pptx": "MS PowerPoint document",
    ".odt": "OpenDocument text", ".ods": "OpenDocument spreadsheet",
    ".odp": "OpenDocument presentation",
}


def check_type_mismatch(extension: str, detected: str):
    """Return True if the real type disagrees with the extension's expectation."""
    ext = extension.lower()
    if ext in EXPECTED_TYPE:
        expected = EXPECTED_TYPE[ext]
        # normalize: 'PNG image' vs 'PNG image'
        if detected.startswith(expected.split()[0]):
            return False
        return True
    return False


# ---------------------------------------------------------------------------
# Framework detection (based on discovered path set)
# ---------------------------------------------------------------------------

FRAMEWORK_SIGNS = {
    "WordPress": ["wp-config.php", "wp-config", "wp-content/", "wp-includes/", "xmlrpc.php"],
    "Laravel": ["artisan", "vendor/laravel", ".env", "storage/logs/", "bootstrap/app.php"],
    "Drupal": ["sites/default/settings.php", "core/lib/Drupal", "web/sites"],
    "Joomla": ["configuration.php", "administrator/", "templates/"],
    "Django": ["manage.py", "settings.py", "wsgi.py", "urls.py"],
    "Flask": ["app.py", "wsgi.py", "flask"],
    "Express": ["package.json", "node_modules/express"],
    "ASP.NET": ["web.config", ".aspx", "global.asax"],
    "Spring Boot": ["pom.xml", "build.gradle", "application.properties", "application.yml"],
    "Symfony": ["symfony.lock", "composer.json", "bin/console"],
    "Next.js": ["next.config.js", ".next/", "next.config.mjs"],
    "React": ["package.json", "src/index.jsx", "src/App.jsx"],
    "Angular": ["angular.json", "src/main.ts", "src/app/app.module.ts"],
    "Vue": ["vue.config.js", "src/main.js", "vite.config.js"],
    "Svelte": ["svelte.config.js", "src/main.ts", "package.json"],
    "Astro": ["astro.config.mjs", "astro.config.ts", "src/pages/"],
    "Nuxt": ["nuxt.config.ts", "nuxt.config.js", "package.json"],
    "Gatsby": ["gatsby-config.js", "gatsby-node.js", "package.json"],
    "Remix": ["remix.config.js", "package.json", "app/root.tsx"],
    "NestJS": ["nest-cli.json", "src/main.ts", "package.json"],
    "FastAPI": ["requirements.txt", "main.py", "pyproject.toml"],
    "Strapi": ["config/admin/", "package.json", "strapi"],
    "Ghost": ["config.production.json", "package.json", "content/themes/"],
    "Magento": ["composer.json", "app/etc/env.php", "bin/magento"],
    "Shopify": ["config/settings_schema.json", "theme.toml", "templates/"],
    "PrestaShop": ["config/settings.inc.php", "config/defines.inc.php"],
    "OpenCart": ["config.php", "admin/config.php", "system/"],
    "OpenAPI/Swagger": ["swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml"],
    "GraphQL": ["schema.graphql", "graphql/", "apollo.config.js"],
    "Kubernetes": ["k8s/", "kubernetes/", "helm/", "chart.yaml", "values.yaml"],
    "Docker Compose": ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"],
    "Terraform": ["main.tf", "variables.tf", "outputs.tf", "terraform.tfvars"],
    "Ansible": ["ansible.cfg", "playbook.yml", "inventory/", "roles/"],
    "Vagrant": ["Vagrantfile", ".vagrant/"],
    "CircleCI": [".circleci/config.yml"],
    "GitHub Actions": [".github/workflows/"],
    "GitLab CI": [".gitlab-ci.yml"],
    "Jenkins": ["Jenkinsfile", "jenkins/"],
    "Azure DevOps": ["azure-pipelines.yml", ".azure/"],
    "Bitbucket Pipelines": ["bitbucket-pipelines.yml"],
}


def detect_frameworks(paths):
    """paths: iterable of lower-case relative paths. Return list of framework names."""
    lowered = set(p.lower() for p in paths)
    found = []
    for fw, signs in FRAMEWORK_SIGNS.items():
        for s in signs:
            # directory-style sign ends with '/'
            if s.endswith("/"):
                if any(pp.startswith(s) for pp in lowered):
                    found.append(fw)
                    break
            else:
                base = s.split("/")[-1]
                if any(pp.endswith("/" + base) or pp == base for pp in lowered):
                    found.append(fw)
                    break
    return found


# ---------------------------------------------------------------------------
# Cloud detection (based on URLs + content strings)
# ---------------------------------------------------------------------------

CLOUD_SIGNS = {
    "AWS": ["amazonaws.com", "s3.amazonaws", "AKIA", "aws.amazon.com", "cloudfront.net", "elasticbeanstalk"],
    "Azure": ["blob.core.windows.net", "azure", "core.windows.net", "azurewebsites.net", "azurecr.io"],
    "Google Cloud": ["storage.googleapis.com", "googleapis.com", "googlecloud", "cloudfunctions.net", "run.app"],
    "Cloudflare": ["cloudflare", "workers.dev", "pages.dev", "r2.dev"],
    "Firebase": ["firebaseio.com", "firebase", "firebaseapp.com", "firestore.googleapis.com"],
    "Supabase": ["supabase.co", "supabase", "supabase.in"],
    "Vercel": ["vercel.app", "vercel", "now.sh", "vercel-dns.com"],
    "Netlify": ["netlify.app", "netlify", "netlify.toml"],
    "DigitalOcean": ["digitalocean", "spaces.cloud", "digitaloceanspaces.com", "ondigitalocean.app"],
    "Railway": ["railway.app", "railway", "railway.internal"],
    "Render": ["render.com", "onrender.com", "render.net"],
    "Heroku": ["herokuapp.com", "heroku.com", "heroku"],
    "Fly.io": ["fly.dev", "fly.io", "fly.toml"],
    "Cloudflare Pages": ["pages.dev"],
    "AWS Lambda": ["lambda-url.", "execute-api."],
    "Cloudflare Workers": ["workers.dev"],
    "Cloudflare R2": ["r2.cloudflarestorage.com"],
    "Backblaze B2": ["backblazeb2.com", "b2-api."],
    "Wasabi": ["wasabisys.com", "wasabi"],
    "MinIO": ["minio", "min.io"],
    "Cloudinary": ["cloudinary.com", "res.cloudinary.com"],
    "Imgix": ["imgix.net"],
    "Fastly": ["fastly.net", "fastlylb.net"],
    "Akamai": ["akamai", "akamaiedge.net", "akamaihd.net"],
    "CloudFront": ["cloudfront.net"],
    "Alibaba Cloud": ["aliyuncs.com", "alicloud", "alibaba"],
    "Tencent Cloud": ["qcloud", "tencent", "myqcloud.com"],
    "Huawei Cloud": ["huaweicloud", "myhuaweicloud.com"],
    "Oracle Cloud": ["oraclecloud.com", "ocir.io", "objectstorage."],
    "IBM Cloud": ["bluemix.net", "cloud.ibm.com", "softlayer"],
}


def detect_clouds(text_bag):
    """text_bag: lower-case string containing URLs + content snippets."""
    bag = text_bag.lower()
    found = []
    for cloud, signs in CLOUD_SIGNS.items():
        for s in signs:
            if s in bag:
                found.append(cloud)
                break
    return found
