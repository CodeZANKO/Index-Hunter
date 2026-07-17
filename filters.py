"""Advanced search filters applied to findings (post-scan or live)."""
import re


class FilterSpec:
    def __init__(self):
        self.severities = set()      # e.g. {"critical","high"}
        self.extensions = set()      # e.g. {".env",".sql"}
        self.categories = set()      # e.g. {"PASSWORD","DATABASE"}
        self.min_size = None         # bytes
        self.max_size = None         # bytes
        self.folder = ""             # substring of path
        self.regex = ""              # regex on URL or filename
        self.keyword = ""            # substring in URL/filename
        self.date_after = None       # datetime
        self.date_before = None      # datetime
        self._rx = None

    def empty(self) -> bool:
        return not (
            self.severities or self.extensions or self.categories
            or self.min_size is not None or self.max_size is not None
            or self.folder or self.regex or self.keyword
            or self.date_after or self.date_before
        )

    def compile(self):
        self._rx = re.compile(self.regex) if self.regex else None


def matches(finding: dict, spec: FilterSpec) -> bool:
    """Return True if a finding passes all active filters."""
    if spec.severities and finding.get("severity") not in spec.severities:
        return False
    if spec.categories and finding.get("category") not in spec.categories:
        return False
    ext = finding.get("extension", "").lower()
    if spec.extensions and ext not in spec.extensions:
        return False
    size = finding.get("size") or 0
    if spec.min_size is not None and size < spec.min_size:
        return False
    if spec.max_size is not None and size > spec.max_size:
        return False
    path = finding.get("path", "")
    if spec.folder and spec.folder.lower() not in path.lower():
        return False
    if spec.keyword and spec.keyword.lower() not in (path + " " + finding.get("url", "")).lower():
        return False
    if spec._rx is not None:
        if not spec._rx.search(finding.get("url", "")) and not spec._rx.search(path):
            return False
    if spec.date_after and (finding.get("last_modified") or 0) < spec.date_after.timestamp():
        return False
    if spec.date_before and (finding.get("last_modified") or 0) > spec.date_before.timestamp():
        return False
    return True
