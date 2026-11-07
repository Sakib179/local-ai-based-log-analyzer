import json

import pytest

from app.services.event_parsing import parse_events, parse_timestamp, supplement_cited_json


def test_common_auth_formats_and_literal_json_fields() -> None:
    failed = parse_events("Nov  7 12:00:00 host sshd[12]: Failed password for invalid user admin from 2001:db8::1 port 22 ssh2\n")[0]
    assert failed.event_type == "auth_failure"
    assert failed.source_ip == "2001:db8::1" and failed.username == "admin"
    assert failed.target == "sshd@host" and failed.time_kind == "yearless"
    successful = parse_events(json.dumps({"timestamp": "2026-11-07T12:01:00Z", "event": "auth_success", "username": "admin", "source_ip": "192.0.2.10", "target": "vpn"}))[0]
    assert successful.event_type == "auth_success"
    assert successful.source_ip == "192.0.2.10" and successful.target == "vpn"


def test_no_fabricated_entities_and_no_assumed_login_success_from_http_200() -> None:
    event = parse_events("Failed login\n")[0]
    assert event.timestamp is event.source_ip is event.identifier is event.username is event.target is None
    events = parse_events('192.0.2.10 - - [07/Nov/2026:12:00:00 +0000] "POST /login HTTP/1.1" 200 12\n')
    assert [e.event_type for e in events] == ["http_request"]
    assert parse_events("Failed login to 192.0.2.99 for user admin\n")[0].source_ip is None


def test_request_payload_cannot_override_access_source_or_remote_user() -> None:
    event = parse_events('192.0.2.10 - alice [07/Nov/2026:12:00:00 +0000] "GET /search?note=from%20192.0.2.99&user=bob HTTP/1.1" 403 12\n')[0]
    assert event.source_ip == "192.0.2.10"
    assert event.username == "alice"


@pytest.mark.parametrize("address,expected", [("192.0.2.10:54321", "192.0.2.10"), ("[2001:db8::1]:54321", "2001:db8::1")])
def test_observed_source_ports_are_not_mistaken_for_unknown_addresses(address: str, expected: str) -> None:
    event = parse_events(json.dumps({"message": "Failed authentication", "source_ip": address}))[0]
    assert event.source_ip == expected


def test_sql_statements_in_normal_debug_errors_do_not_count_as_injection() -> None:
    assert parse_events("ERROR SQL query failed: SELECT name FROM users WHERE id=1\n") == []


def test_timestamp_offsets_naive_and_fractional_seconds() -> None:
    assert parse_timestamp("2026-11-07T12:00:00Z")[0] == parse_timestamp("2026-11-07T18:00:00+06:00")[0]
    assert parse_timestamp("2026-11-07 12:00:00")[1] == "naive"
    event = parse_events("2026-11-07 12:00:00,123 Failed login for admin from 192.0.2.10\n")[0]
    assert event.timestamp == "2026-11-07 12:00:00,123"
    assert parse_timestamp("not a timestamp") == (None, None)


def test_untrusted_json_field_types_and_lone_surrogates_do_not_crash_extraction() -> None:
    assert supplement_cited_json('{"operation":[],"result":{"value":"success"}}') == []
    event = parse_events('{"message":"Failed login","username":"\\ud800","source_ip":[] }')[0]
    assert event.username is None and event.source_ip is None


@pytest.mark.parametrize("value", ["9" * 5000, "²", "999", True, [], {}])
def test_malformed_status_fields_do_not_crash_or_invent_an_http_status(value: object) -> None:
    event = parse_events(json.dumps({"message": "Failed login", "source_ip": "192.0.2.10", "status_code": value}))[0]
    assert event.event_type == "auth_failure" and event.http_status is None


def test_client_controlled_access_log_text_cannot_establish_authentication_outcomes() -> None:
    raw = ('192.0.2.10 - - [07/Nov/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 12 '
           '"-" "Failed login; Successful login from 192.0.2.99 for user admin"\n')
    assert [e.event_type for e in parse_events(raw)] == ["http_request"]
