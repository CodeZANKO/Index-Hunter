"""Async crawler engine: concurrency, robots.txt, ignore rules, dedup, resume.

The scanner walks an "Index of" (directory listing) starting from a root URL,
classifies files against the sensitive patterns, fetches a preview (or full
content) of candidates, and runs deep content analysis.
"""
import asyncio
import hashlib
import json
import os
import re
import time
import urllib.robotparser
from urllib.parse import urljoin, urlparse

from patterns import classify_name
from content import fetch_content, analyze_content, mask_preview
import signatures

try:
    import aiohttp
    from bs4 import BeautifulSoup
except ImportError as e:  # pragma: no cover
    raise SystemExit("Missing core dependency: " + str(e))


class ScanConfig:
    def __init__(self, base_url, workers=10, depth=0, full_scan=False,
                 respect_robots=True, yara_dir=None, plugins_dir=None,
                 ignore_file=None, resume_path=None, max_full=5 * 1024 * 1024):
        self.base_url = base_url.rstrip("/") + "/"
        self.workers = max(1, int(workers))
        self.depth = int(depth)  # 0 = unlimited
        self.full_scan = full_scan
        self.respect_robots = respect_robots
        self.yara_dir = yara_dir
        self.plugins_dir = plugins_dir
        self.ignore_file = ignore_file
        self.resume_path = resume_path
        self.max_full = max_full


def _ext(filename):
    dot = filename.rfind(".")
    return filename[dot:].lower() if dot != -1 else ""


# ---------------------------------------------------------------------------
# Ignore rules (.gitignore style)
# ---------------------------------------------------------------------------

class IgnoreRules:
    def __init__(self, rules):
        self.dir_globs = []     # patterns ending with '/'
        self.file_globs = []    # basename globs
        self.exact = set()      # exact path fragments
        for r in rules:
            r = r.strip()
            if not r or r.startswith("#"):
                continue
            if r.endswith("/"):
                self.dir_globs.append(self._glob(r[:-1]))
            elif "/" in r:
                self.exact.add(r.lower())
            else:
                self.file_globs.append(self._glob(r))

    @staticmethod
    def _glob(pat):
        # convert glob to regex (support * and **)
        rx = re.escape(pat)
        rx = rx.replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        return re.compile(rx + "$", re.IGNORECASE)

    def is_ignored(self, path):
        p = path.lower().strip("/")
        if p in self.exact:
            return True
        parts = p.split("/")
        for d in self.dir_globs:
            for i in range(len(parts)):
                if d.search("/".join(parts[: i + 1])):
                    return True
        base = parts[-1] if parts else ""
        for g in self.file_globs:
            if g.search(base):
                return True
        return False

    @classmethod
    def from_file(cls, path):
        if not path or not os.path.exists(path):
            return cls([])
        with open(path, "r", encoding="utf-8") as fh:
            return cls(fh.readlines())


# ---------------------------------------------------------------------------
# YARA loader (optional)
# ---------------------------------------------------------------------------

def load_yara(rules_dir):
    try:
        import yara
    except ImportError:
        return None
    if not rules_dir or not os.path.isdir(rules_dir):
        return None
    sources = {}
    for fn in os.listdir(rules_dir):
        if fn.endswith((".yar", ".yara")):
            try:
                with open(os.path.join(rules_dir, fn), "r", encoding="utf-8") as fh:
                    sources[fn] = fh.read()
            except Exception:
                continue
    if not sources:
        return None
    try:
        rules = yara.compile(sources=sources)
        return rules
    except Exception as e:
        print(f"[!] YARA compile error: {e}")
        return None


# ---------------------------------------------------------------------------
# Plugin loader (optional)
# ---------------------------------------------------------------------------

def load_plugins(plugins_dir):
    plugins = []
    if not plugins_dir or not os.path.isdir(plugins_dir):
        return plugins
    import importlib.util
    for fn in sorted(os.listdir(plugins_dir)):
        if fn.endswith(".py") and not fn.startswith("_"):
            path = os.path.join(plugins_dir, fn)
            try:
                spec = importlib.util.spec_from_file_location("ds_plugin_" + fn[:-3], path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "run"):
                    plugins.append(mod)
            except Exception as e:
                print(f"[!] plugin {fn} error: {e}")
    return plugins


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0, None: -1}


def _max_sev(a, b):
    return a if _SEV_RANK.get(a, -1) >= _SEV_RANK.get(b, -1) else b


def compute_severity(base_sev, analysis):
    sev = base_sev or "low"
    for s in analysis.get("secrets", []):
        sev = _max_sev(sev, s["severity"])
    if analysis.get("mismatch"):
        sev = _max_sev(sev, "medium")
    if analysis.get("entropy"):
        sev = _max_sev(sev, "medium")
    if analysis.get("yara"):
        sev = _max_sev(sev, "high")
    return sev


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class Scanner:
    def __init__(self, cfg: ScanConfig, callbacks=None):
        self.cfg = cfg
        self.cb = callbacks or {}
        self.visited = set()
        self.queue = asyncio.Queue()
        self.findings = []
        self.all_paths = set()
        self.url_bag = set()
        self.hash_seen = {}
        self.stats = {
            "scanned": 0, "folders": set(), "files_total": 0,
            "requests": 0,
            "start": time.time(), "current_folder": "", "current_file": "",
            "queue": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "frameworks": [], "cloud": [],
        }
        self.robots = None
        self.crawl_delay = 0
        self.ignore = IgnoreRules.from_file(cfg.ignore_file)
        self.yara_rules = load_yara(cfg.yara_dir)
        self.plugins = load_plugins(cfg.plugins_dir)
        self._stop = False
        self._save_counter = 0

    # -- callbacks --
    def _emit(self, name, *args):
        fn = self.cb.get(name)
        if fn:
            try:
                fn(*args)
            except Exception:
                pass

    def _progress(self):
        s = self.stats
        s["queue"] = self.queue.qsize()
        s["folders_count"] = len(s["folders"])
        elapsed = max(time.time() - s["start"], 0.01)
        s["speed"] = round(s["scanned"] / elapsed, 1)
        s["elapsed"] = elapsed
        self._emit("progress", dict(s))

    # -- robots --
    async def _init_robots(self, session):
        if not self.cfg.respect_robots:
            return
        try:
            rp = urllib.robotparser.RobotFileParser()
            robots_url = urljoin(self.cfg.base_url, "/robots.txt")
            self.stats["requests"] += 1
            async with session.get(robots_url, timeout=15) as r:
                txt = await r.text()
            rp.parse(txt.splitlines())
            self.robots = rp
            cd = rp.crawl_delay("*")
            if cd:
                self.crawl_delay = float(cd)
        except Exception:
            self.robots = None

    def _allowed(self, url):
        if self.robots:
            return self.robots.can_fetch("*", url)
        return True

    # -- resume --
    def load_state(self):
        if not self.cfg.resume_path or not os.path.exists(self.cfg.resume_path):
            return False
        try:
            with open(self.cfg.resume_path, "r", encoding="utf-8") as fh:
                st = json.load(fh)
            self.visited = set(st.get("visited", []))
            self.findings = st.get("findings", [])
            for f in self.findings:
                self.all_paths.add(f.get("path", ""))
            pending = st.get("pending", [self.cfg.base_url])
            for u in pending:
                self.queue.put_nowait(u)
            self._emit("log", f"[resume] restored {len(self.visited)} visited, {len(pending)} pending")
            return True
        except Exception as e:
            self._emit("log", f"[resume] failed: {e}")
            return False

    def save_state(self):
        if not self.cfg.resume_path:
            return
        try:
            st = {
                "visited": list(self.visited),
                "findings": self.findings,
                "pending": list(self.queue.queue),
            }
            tmp = self.cfg.resume_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(st, fh, default=str)
            os.replace(tmp, self.cfg.resume_path)
        except Exception:
            pass

    # -- main loop --
    async def run(self, max_runtime: int = 600):
        """Run the scan. Finished event is guaranteed to be emitted."""
        try:
            if not self.load_state():
                self.queue.put_nowait(self.cfg.base_url)

            timeout = aiohttp.ClientTimeout(total=60)
            connector = aiohttp.TCPConnector(limit=self.cfg.workers + 2, ssl=False)
            sem = asyncio.Semaphore(self.cfg.workers)

            async with aiohttp.ClientSession(timeout=timeout, connector=connector,
                                              headers={"User-Agent": "IndexHunter/1.0"}) as session:
                await self._init_robots(session)
                workers = [asyncio.create_task(self._worker(session, sem))
                           for _ in range(self.cfg.workers)]
                try:
                    await asyncio.wait_for(self.queue.join(), timeout=max_runtime)
                except asyncio.TimeoutError:
                    self._emit("log", f"[!] scan timed out after {max_runtime}s")
                self._stop = True
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

            # post-scan: frameworks + cloud
            self.stats["frameworks"] = signatures.detect_frameworks(self.all_paths)
            self.stats["cloud"] = signatures.detect_clouds(" ".join(self.url_bag))
        except Exception as exc:
            self._emit("log", f"[scan fatal] {exc}")
            import traceback
            self._emit("log", traceback.format_exc())
        finally:
            self._progress()
            summary = await self._build_summary()
            self._emit("finished", summary)
            self.stats["finished"] = True

    async def _worker(self, session, sem):
        while True:
            url = await self.queue.get()
            try:
                if self._stop:
                    break
                await self._crawl_dir(session, sem, url)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._emit("log", f"[err] {url}: {e}")
            finally:
                self.queue.task_done()

    async def _crawl_dir(self, session, sem, url):
        if url in self.visited:
            return
        self.visited.add(url)
        if not self._allowed(url):
            self._emit("log", f"[robots] blocked: {url}")
            return

        self.stats["current_folder"] = url
        async with sem:
            try:
                self.stats["requests"] += 1
                async with session.get(url, timeout=30, allow_redirects=True) as resp:
                    if resp.status != 200:
                        return
                    html = await resp.text()
            except Exception:
                return
            if self.crawl_delay:
                await asyncio.sleep(self.crawl_delay)

        self.stats["folders"].add(url)
        base_depth = url[len(self.cfg.base_url):].count("/")
        links = self._parse_links(html, url)
        for href, is_dir, fname in links:
            if self._stop:
                break
            if is_dir:
                if self.cfg.depth and base_depth + 1 > self.cfg.depth:
                    continue
                self._emit("dir", urlparse(href).path.rstrip("/"))
                self.queue.put_nowait(href)
            else:
                await self._evaluate_file(session, sem, href, fname)

    def _parse_links(self, html, base_url):
        out = []
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return out
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("?", "#", "javascript:")):
                continue
            abs_url = urljoin(base_url, href)
            parsed = urlparse(abs_url)
            # stay within same host
            if parsed.netloc != urlparse(self.cfg.base_url).netloc:
                continue
            # must be under base path
            if not abs_url.startswith(self.cfg.base_url):
                continue
            fname = parsed.path.rstrip("/").split("/")[-1]
            is_dir = href.endswith("/")
            out.append((abs_url, is_dir, fname))
        return out

    async def _evaluate_file(self, session, sem, url, fname):
        if self._stop:
            return
        self.stats["files_total"] += 1
        self.stats["scanned"] += 1
        self.stats["current_file"] = fname
        self._progress()

        category, base_sev = classify_name(fname)
        if not category:
            return  # not a sensitive candidate -> skip (no content fetch)
        if self.ignore.is_ignored(urlparse(url).path):
            return

        ext = _ext(fname)
        path = urlparse(url).path
        self.all_paths.add(path)
        self.url_bag.add(url)

        finding = {
            "url": url, "path": path, "filename": fname,
            "category": category, "extension": ext,
            "severity": base_sev, "detected_type": "",
            "mismatch": False, "secrets": [], "entropy": [],
            "cloud": [], "yara": [], "framework": "",
            "size": 0, "sha256": "", "duplicate": False,
            "last_modified": 0, "preview": "",
        }

        # fetch preview/full content
        async with sem:
            self.stats["requests"] += 1
            data, truncated, status = await fetch_content(
                session, url, self.cfg.full_scan, self.cfg.max_full)
        if status == 0 or not data:
            self.findings.append(finding)
            self._maybe_save()
            return

        finding["size"] = len(data)
        sha = hashlib.sha256(data).hexdigest()
        finding["sha256"] = sha
        if sha in self.hash_seen:
            finding["duplicate"] = True
        else:
            self.hash_seen[sha] = url

        # run plugins (may enrich)
        for plug in self.plugins:
            try:
                plug.run(finding, data)
            except Exception:
                pass

        analysis = analyze_content(
            data, fname, ext,
            run_yara=(self.yara_rules.match if self.yara_rules else None),
        )
        finding.update({
            "detected_type": analysis["detected_type"],
            "mismatch": analysis["mismatch"],
            "secrets": analysis["secrets"],
            "entropy": analysis["entropy"],
            "cloud": analysis["cloud"],
            "yara": analysis["yara"],
        })
        if truncated:
            finding["preview"] = mask_preview(data[:8192].decode("utf-8", "ignore"))
        else:
            finding["preview"] = mask_preview(data.decode("utf-8", "ignore"))

        finding["severity"] = compute_severity(base_sev, analysis)

        self.findings.append(finding)
        self._count_sev(finding["severity"])
        self._emit("found", finding)
        self._maybe_save()

    def _count_sev(self, sev):
        if sev in self.stats:
            self.stats[sev] += 1

    def _maybe_save(self):
        self._save_counter += 1
        if self.cfg.resume_path and self._save_counter >= 50:
            self.save_state()
            self._save_counter = 0

    async def _build_summary(self):
        from tree import tree_statistics
        tree_stats = tree_statistics(self.findings)
        return {
            "findings_count": len(self.findings),
            "tree": tree_stats,
            "frameworks": self.stats["frameworks"],
            "cloud": self.stats["cloud"],
            "stats": {k: (len(v) if isinstance(v, set) else v)
                      for k, v in self.stats.items()},
        }

    def stop(self):
        self._stop = True
        # drain queue
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except Exception:
                break
        self.save_state()
