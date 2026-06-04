"""Compatibility exports for scanner tests and older imports."""

from github_scanner.github import (  # noqa: F401
    _find_dep_matches,
    _tokenize,
    clean_version,
    extract_repo_path,
    fetch_file,
    is_version_affected,
    match_against_news,
    parse_dependencies,
    scan_repo,
)
