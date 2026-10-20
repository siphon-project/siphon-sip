"""``@registration.on_change`` carries the registration's current ``state``.

The engine adds ``state`` to the dict on every event, so a ``"snapshot"``
(the re-report after a handler fell behind and events were lost) says whether
the trunk is registered or failed, not only that it exists.
"""
from siphon_sdk import mock_module


def test_the_state_dict_names_the_current_state():
    mock_module.reset()
    mock_module.install()
    seen = []

    @mock_module.get_registration().on_change
    def changed(aor, event_type, state):
        seen.append((aor, event_type, state["state"]))

    registration = mock_module.get_registration()
    registration.add("sip:trunk@example.net", "sip:registrar.example.net",
                     user="trunk", password="secret")
    registration.remove("sip:trunk@example.net")

    assert seen == [
        ("sip:trunk@example.net", "registered", "registered"),
        ("sip:trunk@example.net", "deregistered", None),
    ]
