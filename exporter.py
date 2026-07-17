"""Exporters: CSV, JSON, HTML, Markdown, SARIF (+PDF if reportlab present)."""
import csv
import json
import os
from datetime import datetime, timezone

SEV_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}


def _flatten(f):
    secret_labels = ", ".join(s["label"] for s in f.get("secrets", []))
    entropy_count = len(f.get("entropy", []))
    return {
        "url": f.get("url", ""),
        "path": f.get("path", ""),
        "filename": f.get("filename", ""),
        "category": f.get("category", ""),
        "extension": f.get("extension", ""),
        "severity": f.get("severity", ""),
        "detected_type": f.get("detected_type", ""),
        "type_mismatch": f.get("mismatch", False),
        "secrets": secret_labels,
        "entropy_hits": entropy_count,
        "cloud": ", ".join(f.get("cloud", [])),
        "framework": f.get("framework", "") or "",
        "size": f.get("size", 0),
        "sha256": f.get("sha256", ""),
        "duplicate": f.get("duplicate", False),
    }


def export_csv(findings, path):
    rows = [_flatten(f) for f in findings]
    cols = list(rows[0].keys()) if rows else []
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def export_json(findings, path):
    payload = {
        "tool": "IndexHunter",
        "generated": datetime.now(timezone.utc).isoformat(),
        "count": len(findings),
        "findings": findings,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)


def export_markdown(findings, path):
    lines = ["# IndexHunter Report", "",
             f"- Generated: {datetime.now(timezone.utc).isoformat()}",
             f"- Findings: {len(findings)}", ""]
    for f in findings:
        lines.append(f"## {f.get('severity','').upper()} - {f.get('filename','')}")
        lines.append(f"- URL: {f.get('url','')}")
        lines.append(f"- Category: {f.get('category','')}  Ext: {f.get('extension','')}")
        lines.append(f"- Detected type: {f.get('detected_type','')} (mismatch: {f.get('mismatch', False)})")
        if f.get("secrets"):
            lines.append("- Secrets:")
            for s in f["secrets"]:
                lines.append(f"    - [{s['severity']}] {s['label']}: `{s['sample']}`")
        if f.get("entropy"):
            lines.append(f"- High-entropy hits: {len(f['entropy'])}")
        if f.get("cloud"):
            lines.append(f"- Cloud: {', '.join(f['cloud'])}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def export_html(findings, path):
    rows = []
    for f in findings:
        secrets = "<br>".join(f"[{s['severity']}] {s['label']}: <code>{s['sample']}</code>" for s in f.get("secrets", []))
        rows.append(
            f"<tr><td>{_esc(f.get('severity',''))}</td><td>{_esc(f.get('filename',''))}</td>"
            f"<td>{_esc(f.get('category',''))}</td><td>{_esc(f.get('detected_type',''))}</td>"
            f"<td>{_esc(f.get('url',''))}</td><td>{secrets}</td></tr>"
        )
    html = f"""<html><head><meta charset="utf-8"><title>IndexHunter Report</title>
<style>table{{border-collapse:collapse}}td,th{{border:1px solid #999;padding:4px}}
tr:nth-child(even){{background:#f4f4f4}} .critical{{color:#c00;font-weight:bold}}</style>
</head><body><h1>IndexHunter Report</h1>
<p>Generated {datetime.now(timezone.utc).isoformat()} — {len(findings)} findings</p>
<table><tr><th>Severity</th><th>File</th><th>Category</th><th>Type</th><th>URL</th><th>Secrets</th></tr>
{''.join(rows)}</table></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


def _esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def export_sarif(findings, path):
    rules = {}
    results = []
    for f in findings:
        rule_id = f.get("category") or "SENSITIVE_FILE"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": f"Sensitive file: {rule_id}"},
            "fullDescription": {"text": f"Potentially sensitive file detected ({rule_id})"},
            "defaultConfiguration": {"level": SEV_LEVEL.get(f.get("severity"), "warning")},
        })
        msg = f.get("filename", "") + " " + ", ".join(s["label"] for s in f.get("secrets", []))
        results.append({
            "ruleId": rule_id,
            "level": SEV_LEVEL.get(f.get("severity"), "warning"),
            "message": {"text": msg or "Sensitive file found"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("url", "")}
                }
            }],
        })
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "IndexHunter", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)


def export_pdf(findings, path):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        raise RuntimeError("reportlab not installed; PDF export unavailable (pip install reportlab)")
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4)
    data = [["Severity", "File", "Category", "Type", "URL"]]
    for f in findings:
        data.append([f.get("severity", ""), f.get("filename", ""),
                     f.get("category", ""), f.get("detected_type", ""),
                     f.get("url", "")[:80]])
    t = Table(data, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ]))
    doc.build([Paragraph("IndexHunter Report", styles["Title"]), t])


DISPATCH = {
    "csv": export_csv,
    "json": export_json,
    "markdown": export_markdown,
    "md": export_markdown,
    "html": export_html,
    "sarif": export_sarif,
    "pdf": export_pdf,
}


def export(findings, fmt: str, path: str):
    fmt = fmt.lower()
    if fmt not in DISPATCH:
        raise ValueError(f"Unsupported format: {fmt}")
    DISPATCH[fmt](findings, path)

