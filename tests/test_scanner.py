import pytest
from github_scanner.scanner import _tokenize, _find_dep_matches

def test_tokenize():
    # basic & edge cases
    assert _tokenize("React 18 Critical Vuln") == {"react", "18", "critical", "vuln"}
    assert _tokenize("requests>=2.25.1") == {"requests", "2", "25", "1"}
    assert _tokenize("django-rest-framework") == {"django", "rest", "framework"}
    
    # empty or symbols only
    assert _tokenize("   !!! @#&*...   ") == set()
    assert _tokenize("") == set()

def test_find_dep_matches():
    deps = [
        {"name": "react-router-dom"},
        {"name": "go"},
        {"name": "fastapi"}
    ]
    
    news = [
        {
            "title": "React 18 critical vuln",
            "affected_products": '["React 18", "Next.js"]',
            "threat_level": "CRITICAL"
        },
        {
            "title": "GCP outage",
            "affected_products": '["google-cloud", "django"]', 
            "threat_level": "INFO"
        }
    ]
    
    matches = _find_dep_matches(deps, news)
    
    # 應該只能配對到 react，且 go 不應該誤判匹配到 google-cloud
    assert len(matches) == 1
    assert matches[0]["dep_name"] == "react-router-dom"
    assert matches[0]["news_title"] == "React 18 critical vuln"
    assert matches[0]["threat_level"] == "CRITICAL"