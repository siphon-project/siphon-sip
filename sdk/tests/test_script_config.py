"""Tests for the ``config`` namespace (the ``script_config:`` document)."""

import pytest

from siphon_sdk.mock_module import get_script_config, install, reset

DOCUMENT = {
    "routes": {
        "default": {"gateway": "carrier-a", "weight": 10},
        "prefixes": [
            {"prefix": "+1555", "gateway": "gateway-b.example.com"},
            {"prefix": "+15550100", "gateway": "gateway-c.example.com"},
        ],
    },
    "country_codes": {31: "nl"},
    "limits": {"ratio": 0.5, "enabled": True, "note": None},
}


def setup_function():
    install()
    reset()
    get_script_config().set(DOCUMENT)


def test_get_returns_nested_values():
    from siphon import config

    assert config.get("routes.default.gateway") == "carrier-a"
    assert config.get("routes.default.weight") == 10
    assert config.get("limits.ratio") == 0.5
    assert config.get("limits.enabled") is True
    assert config.get("routes.default") == {"gateway": "carrier-a", "weight": 10}


def test_get_indexes_a_sequence_and_an_integer_key():
    from siphon import config

    assert config.get("routes.prefixes.1.gateway") == "gateway-c.example.com"
    assert config.get("country_codes.31") == "nl"


def test_a_prefix_key_is_not_read_as_the_integer_its_digits_spell():
    from siphon import config

    get_script_config().set({
        "by_prefix": {"+31": "gateway-nl.example.com", 44: "gateway-uk.example.com"},
        "rows": ["first", "second"],
    })

    assert config.get("by_prefix.+31") == "gateway-nl.example.com"
    assert config.get("by_prefix.44") == "gateway-uk.example.com"
    assert config.get("by_prefix.+44", "unset") == "unset"
    assert config.get("rows.+1", "unset") == "unset"
    assert config.get("rows.1") == "second"


def test_get_of_the_empty_key_is_the_whole_document():
    from siphon import config

    assert config.get("") == DOCUMENT


def test_get_returns_the_default_for_a_missing_key():
    from siphon import config

    assert config.get("routes.backup") is None
    assert config.get("routes.backup", "carrier-z") == "carrier-z"
    assert config.get("routes.prefixes.9", "none") == "none"
    assert config.get("routes.prefixes.first", "none") == "none"


def test_get_returns_the_default_for_a_path_through_a_scalar():
    from siphon import config

    assert config.get("routes.default.gateway.host", "unset") == "unset"


def test_get_returns_none_for_an_explicit_null_not_the_default():
    from siphon import config

    assert config.get("limits.note", "fallback") is None


def test_get_hands_out_a_copy_each_time():
    from siphon import config

    first = config.get("routes.default")
    first["gateway"] = "changed-by-the-script"
    config.get("routes.prefixes").clear()

    assert config.get("routes.default.gateway") == "carrier-a"
    assert len(config.get("routes.prefixes")) == 2


def test_set_copies_the_document_it_is_given():
    from siphon import config

    document = {"routes": {"default": "gateway-a.example.com"}}
    get_script_config().set(document)
    document["routes"]["default"] = "changed-after-set"

    assert config.get("routes.default") == "gateway-a.example.com"


def test_set_refuses_a_document_that_is_not_a_mapping():
    with pytest.raises(TypeError):
        get_script_config().set(["not", "a", "mapping"])


def test_require_returns_the_value():
    from siphon import config

    assert config.require("routes.default.gateway") == "carrier-a"


def test_require_raises_naming_the_missing_key():
    from siphon import config

    with pytest.raises(LookupError) as raised:
        config.require("routes.backup.gateway")
    assert str(raised.value) == (
        'script_config key "routes.backup.gateway" is not set (no "backup" under "routes")'
    )

    with pytest.raises(LookupError) as raised:
        config.require("policies")
    assert str(raised.value) == (
        'script_config key "policies" is not set (no "policies" at the top level)'
    )


def test_require_raises_for_a_path_through_a_scalar():
    from siphon import config

    with pytest.raises(LookupError) as raised:
        config.require("routes.default.gateway.host")
    assert str(raised.value) == (
        'script_config key "routes.default.gateway.host" is not set '
        '("routes.default.gateway" is a string, not a mapping or a sequence)'
    )


def test_require_raises_for_an_explicit_null():
    from siphon import config

    with pytest.raises(LookupError) as raised:
        config.require("limits.note")
    assert str(raised.value) == 'script_config key "limits.note" is set to null'


def test_reset_empties_the_document():
    from siphon import config

    reset()
    assert config.get("routes") is None
    assert config.get("") == {}
    with pytest.raises(LookupError):
        config.require("routes")


def test_a_script_routes_by_longest_prefix_and_sees_a_new_table():
    from siphon import config

    def gateway_for(number):
        gateway = config.require("routes.default.gateway")
        longest = -1
        for route in config.get("routes.prefixes", []):
            prefix = route["prefix"]
            if number.startswith(prefix) and len(prefix) > longest:
                gateway, longest = route["gateway"], len(prefix)
        return gateway

    assert gateway_for("+15550100") == "gateway-c.example.com"
    assert gateway_for("+15550199") == "gateway-b.example.com"
    assert gateway_for("+44700900123") == "carrier-a"

    get_script_config().set({"routes": {"default": {"gateway": "carrier-d"}, "prefixes": []}})
    assert gateway_for("+15550100") == "carrier-d"
