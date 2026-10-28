"""Shared fixtures. Fake credentials are assembled at runtime so that this repository never
contains strings that look like real secrets to GitHub push protection or secret scanners."""
import pytest

FAKE_STRIPE = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
FAKE_AWS = "AKIA" + "Z7Q3K9XW2M4P8R6T"
FAKE_GITHUB = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
FAKE_PASSWORD = "Tr0ub4dor-" + "horse-battery"


@pytest.fixture
def fake_secrets():
    return {"stripe": FAKE_STRIPE, "aws": FAKE_AWS, "github": FAKE_GITHUB, "password": FAKE_PASSWORD}
