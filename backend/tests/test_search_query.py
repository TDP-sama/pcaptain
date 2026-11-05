"""parse_query: how a search string becomes conditions (routes/search.py)."""

import pytest

from routes.search import parse_query

KNOWN = {"sip", "rtp", "sdp", "udp", "tcp", "sctp", "dns", "eth", "ip", "isup", "camel"}


def conditions(raw):
    """The non-empty parts of the parsed query, as a plain dict."""
    return {k: v for k, v in vars(parse_query(raw, KNOWN)).items() if v}


@pytest.mark.parametrize("raw, expected", [
    ("sip rtp", {"all": ["sip", "rtp"]}),
    ("sip, rtp", {"all": ["sip", "rtp"]}),
    ("SIP Rtp", {"all": ["sip", "rtp"]}),
    ("sip|dns", {"any": [["sip", "dns"]]}),
    ("sip OR dns", {"any": [["sip", "dns"]]}),
    ("sip or dns", {"any": [["sip", "dns"]]}),
    ("sip !rtp", {"all": ["sip"], "none": ["rtp"]}),
    ("sip -rtp", {"all": ["sip"], "none": ["rtp"]}),
    ("!sip|dns", {"none": ["sip", "dns"]}),
    ("name:camel", {"name": ["camel"]}),
    ("file:camel", {"name": ["camel"]}),
    ("!name:greb", {"not_name": ["greb"]}),
    ("isup|bicc", {"all": ["isup"], "unknown": ["bicc"]}),
])
def test_grammar(raw, expected):
    assert conditions(raw) == expected


def test_unknown_word_searches_filenames():
    # Keeps the original behaviour: a word that is not a protocol matches filenames.
    assert conditions("mawi") == {"name": ["mawi"]}


def test_duplicates_are_dropped():
    assert conditions("sip sip SIP") == {"all": ["sip"]}


def test_empty_query():
    q = parse_query("   ", KNOWN)
    assert q.is_empty()
    assert q.wanted_protocols == set()


def test_wanted_protocols_cover_all_and_any():
    q = parse_query("sip rtp|dns !tcp", KNOWN)
    assert q.wanted_protocols == {"sip", "rtp", "dns"}


def test_a_lone_dash_or_bang_is_not_a_negation():
    # "-" alone is a (filename) word, not "exclude nothing"
    assert conditions("-") == {"name": ["-"]}
