"""Categorized sensitive-file patterns provided by the user.

Each entry maps a file signature (extension or bare/keyword filename) to a
category and a base severity. The scanner uses these for fast first-pass
classification before any content is fetched.
"""

# Categories -> base severity used when no deeper secret is found.
CATEGORY_SEVERITY = {
    "BACKUP": "medium",
    "CONFIG": "medium",
    "DATABASE": "high",
    "PASSWORD": "high",
    "ARCHIVES": "medium",
    "LOG": "low",
    "SOURCE": "low",
    "DOCUMENT": "low",
    "CERT": "high",
    "SCRIPT": "medium",
}

# extension (lower, with dot) -> category
EXTENSION_MAP = {
    # BACKUP FILES
    ".bak": "BACKUP",
    ".backup": "BACKUP",
    ".tar": "BACKUP",
    ".old": "BACKUP",
    ".bkp": "BACKUP",
    ".arc": "BACKUP",
    ".orig": "BACKUP",
    ".save": "BACKUP",
    ".swp": "BACKUP",
    ".swo": "BACKUP",
    "~": "BACKUP",
    # CONFIG FILES
    ".cfg": "CONFIG",
    ".ini": "CONFIG",
    ".conf": "CONFIG",
    ".xml": "CONFIG",
    ".json": "CONFIG",
    ".yml": "CONFIG",
    ".yaml": "CONFIG",
    ".toml": "CONFIG",
    ".env": "CONFIG",
    ".cnf": "CONFIG",
    ".properties": "CONFIG",
    ".config": "CONFIG",
    ".settings": "CONFIG",
    ".plist": "CONFIG",
    ".rc": "CONFIG",
    ".props": "CONFIG",
    # DATABASE FILES
    ".db": "DATABASE",
    ".sql": "DATABASE",
    ".sqlite": "DATABASE",
    ".sqlite3": "DATABASE",
    ".mdb": "DATABASE",
    ".accdb": "DATABASE",
    ".frm": "DATABASE",
    ".ibd": "DATABASE",
    ".myd": "DATABASE",
    ".ndf": "DATABASE",
    ".ora": "DATABASE",
    ".dbf": "DATABASE",
    ".mdf": "DATABASE",
    ".ldf": "DATABASE",
    ".xlsx": "DATABASE",
    ".csv": "DATABASE",
    ".tsv": "DATABASE",
    # PASSWORD / SECRET FILES
    ".pwd": "PASSWORD",
    ".passwd": "PASSWORD",
    ".shadow": "PASSWORD",
    ".htpasswd": "PASSWORD",
    ".wp-config": "PASSWORD",
    ".kdbx": "PASSWORD",
    ".cred": "PASSWORD",
    ".secrets": "PASSWORD",
    ".keychain": "PASSWORD",
    ".pfx": "PASSWORD",
    ".p12": "PASSWORD",
    ".pem": "PASSWORD",
    ".key": "PASSWORD",
    ".crt": "PASSWORD",
    ".cer": "PASSWORD",
    ".der": "PASSWORD",
    ".csr": "PASSWORD",
    ".ovpn": "PASSWORD",
    ".mobileconfig": "PASSWORD",
    # ARCHIVES
    ".zip": "ARCHIVES",
    ".rar": "ARCHIVES",
    ".7z": "ARCHIVES",
    ".gz": "ARCHIVES",
    ".tgz": "ARCHIVES",
    ".bz2": "ARCHIVES",
    ".xz": "ARCHIVES",
    ".zst": "ARCHIVES",
    ".lz4": "ARCHIVES",
    ".jar": "ARCHIVES",
    ".war": "ARCHIVES",
    ".ear": "ARCHIVES",
    ".apk": "ARCHIVES",
    ".ipa": "ARCHIVES",
    ".appx": "ARCHIVES",
    # LOGS
    ".log": "LOG",
    ".log.1": "LOG",
    ".log.2": "LOG",
    # SOURCE CODE / SCRIPTS
    ".php": "SCRIPT",
    ".php3": "SCRIPT",
    ".php4": "SCRIPT",
    ".php5": "SCRIPT",
    ".phtml": "SCRIPT",
    ".py": "SCRIPT",
    ".rb": "SCRIPT",
    ".pl": "SCRIPT",
    ".sh": "SCRIPT",
    ".bash": "SCRIPT",
    ".zsh": "SCRIPT",
    ".cgi": "SCRIPT",
    ".asp": "SCRIPT",
    ".aspx": "SCRIPT",
    ".jsp": "SCRIPT",
    ".do": "SCRIPT",
    ".action": "SCRIPT",
    # DOCUMENTS
    ".pdf": "DOCUMENT",
    ".doc": "DOCUMENT",
    ".docx": "DOCUMENT",
    ".xls": "DOCUMENT",
    ".ppt": "DOCUMENT",
    ".pptx": "DOCUMENT",
    ".odt": "DOCUMENT",
    ".ods": "DOCUMENT",
    ".rtf": "DOCUMENT",
    # CERTIFICATES / KEYS
    ".pem": "CERT",
    ".crt": "CERT",
    ".cer": "CERT",
    ".der": "CERT",
    ".p12": "CERT",
    ".pfx": "CERT",
    ".key": "CERT",
    ".csr": "CERT",
    ".p7b": "CERT",
    ".p7c": "CERT",
}

# Bare / keyword filenames (case-insensitive) -> category.
# These catch files that have no extension or a misleading one.
BARE_NAME_MAP = {
    "wp-config": "PASSWORD",
    "wp-config.php": "PASSWORD",
    ".env": "CONFIG",
    ".htpasswd": "PASSWORD",
    ".htaccess": "CONFIG",
    "passwd": "PASSWORD",
    "shadow": "PASSWORD",
    "id_rsa": "PASSWORD",
    "id_dsa": "PASSWORD",
    "id_ecdsa": "PASSWORD",
    "id_ed25519": "PASSWORD",
    "config": "CONFIG",
    "configuration": "CONFIG",
    "settings": "CONFIG",
    "settings.php": "CONFIG",
    "database": "DATABASE",
    "backup": "BACKUP",
    "credentials": "PASSWORD",
    "credential": "PASSWORD",
    "secret": "PASSWORD",
    "secrets": "PASSWORD",
    "private": "PASSWORD",
    "docker-compose.yml": "CONFIG",
    "docker-compose.yaml": "CONFIG",
    "dockerfile": "CONFIG",
    "vagrantfile": "CONFIG",
    "ansible.cfg": "CONFIG",
    "package.json": "CONFIG",
    "composer.json": "CONFIG",
    "gemfile": "CONFIG",
    "requirements.txt": "CONFIG",
    "pipfile": "CONFIG",
    "pom.xml": "CONFIG",
    "build.gradle": "CONFIG",
    "webpack.config.js": "CONFIG",
    "vite.config.js": "CONFIG",
    ".gitignore": "CONFIG",
    ".gitconfig": "CONFIG",
    ".npmrc": "CONFIG",
    ".yarnrc": "CONFIG",
    "authorized_keys": "PASSWORD",
    "known_hosts": "CONFIG",
    "id_rsa.pub": "PASSWORD",
    "id_dsa.pub": "PASSWORD",
    "id_ecdsa.pub": "PASSWORD",
    "id_ed25519.pub": "PASSWORD",
}

# Extra keyword substrings that strongly imply sensitivity when present
# anywhere in a filename.
KEYWORD_HINTS = (
    "backup", "bak", "old", "config", "conf", "credential", "secret",
    "password", "passwd", "db", "database", "sql", "dump", "private",
    ".env", "key", "token", "wp-config",
    "docker", "kube", "ansible", "terraform", "vault",
    "jwt", "oauth", "saml", "ldap", "kerberos",
    "ssh", "tls", "ssl", "cert", "pem", "key",
    "api_key", "apikey", "access_token", "refresh_token",
    "client_secret", "client_id", "webhook",
)


def classify_name(filename: str):
    """Return (category, severity) for a filename, or (None, None)."""
    name = filename.strip()
    lower = name.lower()

    # bare-name match first (most specific)
    if lower in BARE_NAME_MAP:
        cat = BARE_NAME_MAP[lower]
        return cat, CATEGORY_SEVERITY[cat]

    # extension match
    dot = lower.rfind(".")
    if dot != -1:
        ext = lower[dot:]
        if ext in EXTENSION_MAP:
            cat = EXTENSION_MAP[ext]
            return cat, CATEGORY_SEVERITY[cat]

    # keyword hint fallback (lower severity, still worth flagging)
    for kw in KEYWORD_HINTS:
        if kw in lower:
            # guess category from keyword
            if kw in ("backup", "bak", "old"):
                return "BACKUP", "low"
            if kw in ("config", "conf"):
                return "CONFIG", "low"
            if kw in ("db", "database", "sql", "dump"):
                return "DATABASE", "medium"
            if kw in ("credential", "secret", "password", "passwd", "key", "token", "wp-config"):
                return "PASSWORD", "medium"
            if kw == ".env":
                return "CONFIG", "medium"

    return None, None
