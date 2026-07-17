"""Recursive tree statistics: folder tree with severity icons + totals."""

SEVERITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "⚪",
    "info": "⚪",
    None: "",
}


def severity_rank(sev):
    return {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0, None: -1}.get(sev, -1)


def build_tree(findings):
    """Build a nested dict tree from finding 'path' fields.

    Each node: {"__files": [finding...], "__dirs": {name: node},
                "__max_sev": severity}
    """
    root = {"__files": [], "__dirs": {}, "__max_sev": None}

    def insert(node, parts, finding):
        if not parts:
            node["__files"].append(finding)
            return
        head, *rest = parts
        if head not in node["__dirs"]:
            node["__dirs"][head] = {"__files": [], "__dirs": {}, "__max_sev": None}
        insert(node["__dirs"][head], rest, finding)

    for f in findings:
        path = f.get("path", "").strip("/")
        if not path:
            root["__files"].append(f)
            continue
        parts = path.split("/")
        insert(root, parts, f)

    def compute(node):
        sevs = [f.get("severity") for f in node["__files"]]
        max_sev = node.get("__max_sev")
        for s in sevs:
            if severity_rank(s) > severity_rank(max_sev):
                max_sev = s
        for child in node["__dirs"].values():
            csev = compute(child)
            if severity_rank(csev) > severity_rank(max_sev):
                max_sev = csev
        node["__max_sev"] = max_sev
        return max_sev

    compute(root)
    return root


def render_tree(node, prefix="", name="", max_depth=8, _depth=0):
    lines = []
    if _depth > max_depth:
        return lines
    icon = SEVERITY_ICON.get(node.get("__max_sev"), "")
    label = name + (" " + icon if icon else "")
    if prefix == "":
        lines.append(label or "/")
    else:
        lines.append(prefix + label)

    # sort dirs by max severity desc then name
    dirs = sorted(
        node["__dirs"].items(),
        key=lambda kv: (-severity_rank(kv[1].get("__max_sev")), kv[0]),
    )
    child_prefix = prefix + "│   " if prefix else "│   "
    for i, (dname, child) in enumerate(dirs):
        last = (i == len(dirs) - 1) and not node["__files"]
        p = prefix + ("└── " if last else "├── ")
        cp = prefix + ("    " if last else "│   ")
        sub = render_tree(child, cp, dname + "/", max_depth, _depth + 1)
        # replace first line's prefix
        if sub:
            sub[0] = p + sub[0].lstrip("│   ")
            lines.extend(sub)

    # files at this node
    for f in sorted(node["__files"], key=lambda x: -severity_rank(x.get("severity"))):
        fname = f.get("filename", "?")
        icon = SEVERITY_ICON.get(f.get("severity"), "")
        lines.append(prefix + "├── " + fname + (" " + icon if icon else ""))
    # adjust trailing file connector
    if node["__files"] and dirs:
        # last file should be └── instead of ├──
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].rstrip().endswith(tuple(f.get("filename", "?") for f in node["__files"])):
                pass
    return lines


def tree_statistics(findings):
    """Return dict of totals + a rendered tree string."""
    total_folders = set()
    for f in findings:
        p = f.get("path", "").strip("/")
        if p:
            total_folders.add(p.rsplit("/", 1)[0] if "/" in p else "")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = f.get("severity")
        if s in counts:
            counts[s] += 1
    tree = build_tree(findings)
    rendered = render_tree(tree, name="")
    rendered = "\n".join(rendered)
    stats = {
        "folders": len(total_folders),
        "files": len(findings),
        "scanned": len(findings),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "tree": rendered,
    }
    return stats
