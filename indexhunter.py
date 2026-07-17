"""IndexHunter entry point.

Launches the web UI by default (FastAPI). If --url is supplied, runs a
headless scan and writes the requested export.

Usage (web UI):
    python indexhunter.py --web          # http://127.0.0.1:8000

Usage (headless):
    python indexhunter.py --url http://example.com/backups/ --workers 20 \
        --format json --output report.json
"""
import argparse
import asyncio
import os
import sys

from scanner import Scanner, ScanConfig


def _headless(cfg, output, fmt):
    states = {"last_print": 0}

    def on_progress(s):
        # light throttled logging
        import time
        now = time.time()
        if now - states["last_print"] < 1.0:
            return
        states["last_print"] = now
        print(f"\r[scan] scanned={s.get('scanned',0)} queue={s.get('queue',0)} "
              f"crit={s.get('critical',0)} high={s.get('high',0)} "
              f"speed={s.get('speed',0)}/s", end="", flush=True)

    def on_found(f):
        tag = f.get("severity", "").upper()
        print(f"\n  [{tag}] {f['filename']} ({f['category']}) -> {f['url']}")
        for sec in f.get("secrets", []):
            print(f"      secret: [{sec['severity']}] {sec['label']}: {sec['sample']}")

    def on_log(m):
        print(m)

    def on_finished(summary):
        ts = summary.get("tree", {})
        print("\n=== Scan finished ===")
        print(f"Findings: {summary.get('findings_count', 0)}")
        print(f"Critical: {ts.get('critical',0)} High: {ts.get('high',0)} "
              f"Medium: {ts.get('medium',0)} Low: {ts.get('low',0)}")
        print(f"Frameworks: {', '.join(summary.get('frameworks', [])) or 'none'}")
        print(f"Cloud hints: {', '.join(summary.get('cloud', [])) or 'none'}")
        if output:
            from exporter import export as export_findings
            try:
                export_findings(scanner.findings, fmt, output)
                print(f"Exported -> {output} ({fmt})")
            except Exception as e:
                print(f"Export failed: {e}")

    scanner = Scanner(cfg, callbacks={
        "progress": on_progress, "found": on_found,
        "log": on_log, "finished": on_finished,
    })

    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        scanner.stop()
        print("\n[interrupted]")


def main():
    parser = argparse.ArgumentParser(
        description="IndexHunter — advanced 'Index of' sensitive-file scanner")
    parser.add_argument("--url", help="Target 'Index of' URL (enables headless mode)")
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--depth", type=int, default=0, help="0 = unlimited")
    parser.add_argument("--full", action="store_true", help="Download full matched files")
    parser.add_argument("--no-robots", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--yara-dir", default=os.path.join(os.path.dirname(__file__), "yara_rules"))
    parser.add_argument("--plugins-dir", default=os.path.join(os.path.dirname(__file__), "plugins"))
    parser.add_argument("--ignore", default=None)
    parser.add_argument("--format", default="json",
                        choices=["csv", "json", "html", "markdown", "md", "sarif", "pdf"])
    parser.add_argument("--output", default=None, help="Export file path")
    parser.add_argument("--web", action="store_true", help="Launch the web UI (FastAPI)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    # Default to the web UI unless a target URL (headless scan) is given.
    if not args.url:
        import uvicorn
        print(f"IndexHunter web UI: http://{args.host}:{args.port}")
        uvicorn.run("server:app", host=args.host, port=args.port, log_level="info")
        return

    url = args.url.rstrip("/") + "/"
    resume_path = None
    if args.resume:
        resume_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "indexhunter_resume.json")

    cfg = ScanConfig(
        base_url=url, workers=args.workers, depth=args.depth,
        full_scan=args.full, respect_robots=not args.no_robots,
        yara_dir=args.yara_dir, plugins_dir=args.plugins_dir,
        ignore_file=args.ignore, resume_path=resume_path,
    )
    output = args.output or (f"indexhunter_report.{args.format}")
    _headless(cfg, output, args.format)


if __name__ == "__main__":
    main()
