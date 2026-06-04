import pytest
import pipeline

@pytest.fixture
def mock_dependencies(monkeypatch):
    monkeypatch.setattr("pipeline.crawl_all_feeds", lambda: 5)
    monkeypatch.setattr("pipeline.fetch_recent_cves", lambda days_back=1: 2)
    monkeypatch.setattr("pipeline.analyze_pending_news", lambda: 3)
    monkeypatch.setattr("pipeline.record_crawl_run", lambda *args, **kwargs: None)

def test_run_crawl_cycle_success(mock_dependencies):
    if pipeline._lock.locked():
        pipeline._lock.release()

    ran, msg = pipeline.run_crawl_cycle()
    
    assert ran is True
    assert "爬取完成" in msg
    assert not pipeline._lock.locked()

def test_run_crawl_cycle_mutex_blocked():
    pipeline._lock.acquire()
    
    try:
        ran, msg = pipeline.run_crawl_cycle()
        
        assert ran is False
        assert "請稍候" in msg
        assert pipeline._lock.locked()
    finally:
        pipeline._lock.release()