import time

from vuln_agent.redaction import is_placeholder, mask, redact_text


PEM_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"
PEM_FOOTER = "-----END RSA " + "PRIVATE KEY-----"


def test_mask_keeps_prefix_and_hides_length(fake_secrets):
    assert mask(fake_secrets["aws"]) == "AKIA********"
    assert mask("short") == "********"


def test_redacts_known_tokens_and_assignments(fake_secrets):
    text = (f'aws = "{fake_secrets["aws"]}"\n'
            f'gh = {fake_secrets["github"]}\n'
            f'DB_PASSWORD = "{fake_secrets["password"]}"\n')
    redacted = redact_text(text)
    for value in fake_secrets.values():
        if value in text:
            assert value not in redacted
    assert "AKIA********" in redacted


def test_redacts_private_key_body():
    pem = f"{PEM_HEADER}\nMIIEowIBAAKCAQEAsecretbody\nmore==\n{PEM_FOOTER}"
    redacted = redact_text(pem)
    assert "MIIEowIBAAKCAQEAsecretbody" not in redacted
    assert PEM_HEADER in redacted


def test_redaction_is_idempotent(fake_secrets):
    once = redact_text(f'token: "{fake_secrets["stripe"]}"')
    assert redact_text(once) == once


def test_placeholders_are_not_secrets():
    for value in ("changeme123", "${API_KEY}", "<your-token>", "https://example.com/oauth/token", "xxxxxxxxxx"):
        assert is_placeholder(value)
    assert not is_placeholder("Tr0ub4dor-horse")


def test_redaction_is_linear_on_hostile_input():
    hostile = ("sk-" * 120_000) + ("eyJ" * 120_000) + ("a" * 300_000) + 'password = "'
    start = time.perf_counter()
    redact_text(hostile)
    assert time.perf_counter() - start < 5
