import json

from vuln_agent.feed_analysis import analyze_feed, analyze_feed_json, decode_base64_url

# broadcastUrl/liveTrackerUrl strings taken verbatim from a captured feed (public odds data).
BROADCAST = ("https://video-translations.top-parser.com/sm/iframe?ref="
             "aHR0cHM6Ly9zbWQuc3BvcnRwbGF5ZXIuaW8vZW1iZWQucGhwLz9tYXRjaF9pZD00NDgwNzc1NyZzaz1hNWUwMDEzJnR5cGU9cw"
             "&t=1793226600&lang=pt")
TRACKER = "https://video-translations.top-parser.com/p/https://bet-broadcast.com/tracker/get/69151053?s=1&lang=pt"

FEED = {"feed": [{"sportId": 18, "sportName": "Futebol", "matches": [
    {"id": 1, "slug": "flu-vs-inter", "awayTeamName": "SC Internacional", "awayTeamSlug": "sc-internacional",
     "homeTeamLogoUrl": "https://bstatic.live/team-icons/10-1.webp",
     "broadcastUrl": BROADCAST, "liveTrackerUrl": TRACKER,
     "oddGroups": [{"name": "Resultado do tempo regulamentar", "odds": [
         {"coefficient": 5.03, "outCome": "1"}, {"coefficient": 3.02, "outCome": "x"},
         {"coefficient": 1.92, "outCome": "2"}]}]},
    {"id": 2, "slug": "fc-new-york-vs-atlanta-united", "awayTeamName": "Fakenham Town",
     "awayTeamSlug": "atlanta-united",
     "broadcastUrl": BROADCAST.replace("t=1793226600", "t=1793230200"), "oddGroups": []},
]}]}


def rules(findings):
    return {f["rule_id"] for f in findings}


def test_decode_base64_url():
    decoded = decode_base64_url(
        "aHR0cHM6Ly9zbWQuc3BvcnRwbGF5ZXIuaW8vZW1iZWQucGhwLz9tYXRjaF9pZD00NDgwNzc1NyZzaz1hNWUwMDEzJnR5cGU9cw")
    assert decoded == "https://smd.sportplayer.io/embed.php/?match_id=44807757&sk=a5e0013&type=s"
    assert decode_base64_url("not base64 !!") is None
    assert decode_base64_url("dGhpcyBpcyBwbGFpbiB0ZXh0") is None  # valid base64, not a URL


def test_detects_hosts_base64_proxy_and_shared_key():
    findings, meta = analyze_feed(FEED)
    assert rules(findings) == {
        "vulnagent.feed.third-party-host", "vulnagent.feed.base64-url",
        "vulnagent.feed.url-in-path-proxy", "vulnagent.feed.shared-key"}
    hosts = meta["feed_summary"]["active_third_party_hosts"]
    assert "smd.sportplayer.io" in hosts  # revealed only after base64 decode
    assert "bet-broadcast.com" in hosts   # revealed only from the URL-in-path proxy
    assert "video-translations.top-parser.com" in hosts
    assert meta["feed_summary"]["asset_hosts"] == ["bstatic.live"]  # CDN separated out


def test_base64_url_is_informational_not_a_vulnerability():
    findings, _ = analyze_feed(FEED)
    b64 = next(f for f in findings if f["rule_id"] == "vulnagent.feed.base64-url")
    assert b64["severity"] == "Info"
    assert b64["triage_status"] == "not_reportable_as_is"
    assert "sk=a5e0013" in b64["evidence"]


def test_url_in_path_proxy_needs_impact_validation():
    findings, _ = analyze_feed(FEED)
    proxy = next(f for f in findings if f["rule_id"] == "vulnagent.feed.url-in-path-proxy")
    assert proxy["triage_status"] == "needs_impact_validation"
    assert "bet-broadcast.com" in proxy["evidence"]


def test_shared_key_is_site_wide_not_user_secret():
    findings, _ = analyze_feed(FEED)
    keys = {f["evidence"] for f in findings if f["rule_id"] == "vulnagent.feed.shared-key"}
    assert "sk=a5e0013" in keys
    assert not any(e in ("s=1", "type=s") for e in keys)  # trivial flags filtered out
    shared = next(f for f in findings if f["rule_id"] == "vulnagent.feed.shared-key")
    assert shared["triage_status"] == "not_reportable_as_is"
    assert "não é um token por usuário" in shared["description"].lower() or "NÃO um token" in shared["description"]


def test_margins_and_slug_mismatch_in_summary():
    _, meta = analyze_feed(FEED)
    summary = meta["feed_summary"]
    margins = {m["match"]: m["overround_pct"] for m in summary["market_margins"]}
    assert abs(margins["flu-vs-inter"] - 5.08) < 0.1
    assert summary["team_slug_mismatches"] == [{"id": 2, "name": "Fakenham Town", "slug": "atlanta-united"}]


def test_analyze_feed_json_rejects_bad_json():
    import pytest
    with pytest.raises(ValueError):
        analyze_feed_json("{not json")
    findings, _ = analyze_feed_json(json.dumps(FEED))
    assert findings
