"""Destination retarget on the LCR answer (RFC 3261 §16.5).

Inbound calls addressed to a local access number need the routing answer to name
the real destination. `tech_prefix` only prepends, and `ruri` replaces the whole
Request-URI — which forces the API to compose each carrier's host by hand,
bypassing gateway-group member selection and health checks entirely.

`destination` replaces the dialled *number* before the ordinary dial path runs,
so `tech_prefix`, `number_policy` and group selection all still apply on top.
"""

from siphon_sdk.lcr import LcrResponse, Route


def test_route_destination_round_trips():
    route = Route(carrier_id="a", gateway_group="carriers", destination="+12025550199")

    assert route.to_dict()["destination"] == "+12025550199"
    assert Route.from_dict(route.to_dict()).destination == "+12025550199"


def test_destination_is_absent_from_the_wire_when_unset():
    """The contract stays additive: an API that never sets it sees no change."""
    route = Route(carrier_id="a", gateway_group="carriers")

    assert "destination" not in route.to_dict()
    assert "destination" not in LcrResponse(routes=[route]).to_dict()


def test_answer_level_destination_round_trips():
    response = LcrResponse(
        routes=[Route(carrier_id="a", gateway_group="carriers")],
        destination="+12025550199",
    )

    assert response.to_dict()["destination"] == "+12025550199"
    assert LcrResponse.from_dict(response.to_dict()).destination == "+12025550199"


def test_answer_level_destination_applies_to_routes_without_their_own():
    response = LcrResponse(
        destination="+12025550199",
        routes=[
            Route(carrier_id="a", gateway_group="carriers"),
            Route(carrier_id="b", gateway_group="carriers", destination="+12025550188"),
        ],
    )

    resolved = response.resolved_routes()
    assert resolved[0].destination == "+12025550199"
    assert resolved[1].destination == "+12025550188", "a route's own destination wins"


def test_resolving_does_not_mutate_the_original_routes():
    original = Route(carrier_id="a", gateway_group="carriers")
    response = LcrResponse(routes=[original], destination="+12025550199")

    response.resolved_routes()
    assert original.destination is None


def test_no_answer_level_destination_leaves_routes_alone():
    response = LcrResponse(routes=[Route(carrier_id="a", gateway_group="carriers")])

    assert response.resolved_routes()[0].destination is None


def test_a_full_response_parses_from_the_api_json():
    """The shape an API actually returns for a retargeted inbound call."""
    response = LcrResponse.from_dict(
        {
            "destination": "+12025550199",
            "cache_ttl_secs": 0,
            "routes": [
                {
                    "carrier_id": "carrier-a",
                    "gateway_group": "carriers",
                    "tech_prefix": "1010288",
                },
                {
                    "carrier_id": "carrier-b",
                    "gateway_group": "carriers",
                    "destination": "+12025550188",
                },
            ],
        }
    )

    resolved = response.resolved_routes()
    assert [r.destination for r in resolved] == ["+12025550199", "+12025550188"]
    # Group selection and the prefix are untouched by the retarget.
    assert resolved[0].gateway_group == "carriers"
    assert resolved[0].tech_prefix == "1010288"
