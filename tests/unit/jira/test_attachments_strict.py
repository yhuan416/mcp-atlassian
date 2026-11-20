"""Fork-specific tests: strict attachment download (no redirects, no login pages)."""

import io
from unittest.mock import MagicMock, patch

import pytest


class _FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, status=200, headers=None, chunks=None):
        self.status_code = status
        self.headers = headers or {}
        self._chunks = chunks or []

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=8192):
        yield from self._chunks

    def close(self):
        pass


@pytest.fixture
def mixin(jira_fetcher):
    jira_fetcher.jira = MagicMock()
    jira_fetcher.jira._session = MagicMock()
    jira_fetcher.jira.url = "https://test.url"
    return jira_fetcher


def _call(mixin, response, target, size=None, mime="text/plain"):
    mixin.jira._session.get.return_value = response
    with (
        patch("os.makedirs"),
        patch("os.replace"),
        patch("mcp_atlassian.jira.attachments.validate_safe_path"),
        patch("mcp_atlassian.jira.attachments.is_in_cwd_root", return_value=False),
        patch("mcp_atlassian.jira.attachments.get_file_root", return_value="/tmp/dl"),
        patch("mcp_atlassian.jira.attachments.open_confined", side_effect=lambda p, m: io.BytesIO()),
    ):
        return mixin.download_attachment_strict(
            "https://test.url/attachment", target, expected_size=size, expected_mime=mime
        )


def test_redirect_is_rejected(mixin):
    resp = _FakeResponse(
        status=302, headers={"Location": "/login.jsp?permissionViolation=true"}
    )
    ok, err = _call(mixin, resp, "/tmp/dl/a.log", size=10)
    assert ok is False
    assert "redirect" in err.lower()


def test_login_page_is_rejected(mixin):
    html = b"<!DOCTYPE html><html><head><title>\xe7\x99\xbb\xe5\xbd\x95 - Jira</title></head></html>"
    resp = _FakeResponse(
        status=200,
        headers={"Content-Type": "text/html;charset=UTF-8"},
        chunks=[html],
    )
    ok, err = _call(mixin, resp, "/tmp/dl/a.log", size=len(html))
    assert ok is False
    assert "html" in err.lower()


def test_size_mismatch_is_rejected(mixin):
    resp = _FakeResponse(
        status=200,
        headers={"Content-Type": "text/plain"},
        chunks=[b"x" * 100],
    )
    ok, err = _call(mixin, resp, "/tmp/dl/a.log", size=1000)
    assert ok is False
    assert "size mismatch" in err.lower()


def test_good_file_passes(mixin):
    data = b"2026-11-16 09:56:09 dsp log line\n" * 10
    resp = _FakeResponse(
        status=200,
        headers={"Content-Type": "text/plain"},
        chunks=[data],
    )
    ok, err = _call(mixin, resp, "/tmp/dl/a.log", size=len(data))
    assert ok is True
    assert err == ""
    mixin.jira._session.get.assert_called_with(
        "https://test.url/attachment", stream=True, allow_redirects=False
    )

def test_session_cookie_is_sent(mixin, monkeypatch):
    data = b"log line\n" * 20
    resp = _FakeResponse(
        status=200, headers={"Content-Type": "text/plain"}, chunks=[data]
    )
    monkeypatch.setenv("JIRA_SESSION_COOKIE", "JSESSIONID=abc123; atlassian.xsrf.token=xyz")
    ok, _ = _call(mixin, resp, "/tmp/dl/a.log", size=len(data))
    assert ok is True
    _, kwargs = mixin.jira._session.get.call_args
    assert kwargs["headers"] == {"Cookie": "JSESSIONID=abc123; atlassian.xsrf.token=xyz"}
    assert kwargs["allow_redirects"] is False


def test_expired_cookie_hint(mixin, monkeypatch):
    monkeypatch.setenv("JIRA_SESSION_COOKIE", "JSESSIONID=stale")
    resp = _FakeResponse(status=302, headers={"Location": "/login.jsp"})
    ok, err = _call(mixin, resp, "/tmp/dl/a.log")
    assert ok is False
    assert "JIRA_SESSION_COOKIE" in err and "expired" in err
