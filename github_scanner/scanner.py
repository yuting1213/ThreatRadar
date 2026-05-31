"""
Scan a GitHub repository for dependency files and match against
CVE-affected products found in the news database.
"""

import requests
import json
import re
import xml.etree.ElementTree as ET
from packaging.version import Version
from packaging.specifiers import SpecifierSet
from database.db import get_recent_news, save_github_scan

def extract_repo_path(repo_url: str) -> str:
    """
    Extract 'owner/repo' from various GitHub URL formats.
    e.g. https://github.com/owner/repo -> owner/repo
    """
    match = re.search(r'github\.com/([^/]+/[^/]+?)(?:\.git|/|$)', repo_url)
    return match.group(1) if match else ""


def fetch_file(repo_path: str, filename: str) -> str:
    """
    Fetch raw file content from GitHub.
    Uses unauthenticated API (60 req/hour limit).
    """
    url = f"https://api.github.com/repos/{repo_path}/contents/{filename}"
    resp = requests.get(url, headers={"Accept": "application/vnd.github.raw+json"}, timeout=10)
    if resp.status_code == 200:
        return resp.text
    return ""


def parse_dependencies(repo_path: str) -> list[dict]:
    """
    Try to fetch and parse these dependency files:
    - requirements.txt (Python)
    - package.json (Node.js)
    - pom.xml (Java, basic)
    - go.mod (Go, basic)

    Return list of {"name": str, "version": str} dicts.
    """
    deps = []

    # requirements.txt
    content = fetch_file(repo_path, "requirements.txt")
    if content:
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                # Handle: package==1.0, package>=1.0, package
                m = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*[><=!]*([\d\.]*)', line)
                if m:
                    deps.append({"name": m.group(1).lower(), "version": m.group(2)})

    # package.json
    content = fetch_file(repo_path, "package.json")
    if content:
        try:
            pkg = json.loads(content)
            for section in ["dependencies", "devDependencies"]:
                for name, version in pkg.get(section, {}).items():
                    deps.append({"name": name.lower(), "version": version.lstrip("^~>=")})
        except Exception:
            pass

    return deps


# Short or generic dep names cause noisy substring matches in the old
# implementation (e.g. dep "go" matching product "google-cloud", dep "py"
# matching "PyPy", etc.). They're never used as a primary match key.
SHORT_NAME_BLACKLIST = {
    "js", "go", "py", "ts", "rb", "c", "cpp", "rs",
    "io", "ai", "ui", "db", "os", "core", "lib", "util",
}

_TOKEN_SPLIT = re.compile(r'[^a-z0-9]+')


def _tokenize(text: str) -> set[str]:
    """Lowercase + split on non-alphanumeric. Empty tokens dropped."""
    return {t for t in _TOKEN_SPLIT.split(text.lower()) if t}


def _find_dep_matches(dependencies: list[dict], news_items: list[dict]) -> list[dict]:
    """
    Pure matching logic — separated from the DB read so it's unit-testable.

    Rule: a dep name (or its first hyphen-separated component, if long enough)
    must appear as a whole token in some affected_products entry. The old
    substring rule produced false positives like dep "go" matching product
    "google-cloud" and dep "django" matching product "go".

    `react-router-dom` also matches products that just say "React", because
    its first token "react" is added as a secondary candidate.
    """
    # candidate token -> original dep dict (keeps the user-facing name).
    candidates: dict[str, dict] = {}
    for d in dependencies:
        name = d["name"].lower()
        if name in SHORT_NAME_BLACKLIST:
            continue
        candidates.setdefault(name, d)
        first = name.split("-")[0]
        if first != name and len(first) >= 4 and first not in SHORT_NAME_BLACKLIST:
            candidates.setdefault(first, d)

    matches = []
    for item in news_items:
        raw = item.get("affected_products")
        if not raw:
            continue
        try:
            products = json.loads(raw)
        except Exception:
            continue
        if not products:
            continue

        # Pool every product's tokens for this news item.
        product_tokens: set[str] = set()
        for product in products:
            product_tokens |= _tokenize(product)

        for candidate_name, dep in candidates.items():
            if candidate_name in product_tokens:
                matches.append({
                    "dep_name":       dep["name"],
                    "news_title":     item["title"],
                    "threat_level":   item.get("threat_level", "INFO"),
                    "action_summary": item.get("action_summary", ""),
                    "url":            item.get("url", ""),
                })
                break  # one match per news item

    return matches


def match_against_news(dependencies: list[dict]) -> list[dict]:
    """Match dep names against affected_products tokens from recent news."""
    return _find_dep_matches(dependencies, get_recent_news(limit=200))


def scan_repo(repo_url: str) -> dict:
    """
    Full scan pipeline:
    1. Extract repo path
    2. Fetch dependencies
    3. Match against news DB
    4. Save to DB
    5. Return result dict

    Return: {"repo_url", "deps_found", "matches", "error"}
    """
    if not repo_url or "github.com" not in repo_url:
        return {"error": "請輸入有效的 GitHub repo URL"}

    repo_path = extract_repo_path(repo_url)
    if not repo_path:
        return {"error": "無法解析 repo 路徑"}

    try:
        deps = parse_dependencies(repo_path)
        if not deps:
            return {
                "repo_url": repo_url,
                "deps_found": 0,
                "matches": [],
                "error": "找不到依賴檔案（requirements.txt 或 package.json）",
            }

        matches = match_against_news(deps)
        save_github_scan(repo_url, json.dumps(deps), json.dumps(matches))

        return {
            "repo_url":   repo_url,
            "deps_found": len(deps),
            "matches":    matches,
            "error":      None,
        }
    except Exception as e:
        return {"error": str(e)}
