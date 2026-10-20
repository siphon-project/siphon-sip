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


def test_a_registrar_handler_that_takes_sequence_gets_rising_numbers():
    mock_module.reset()
    mock_module.install()
    registrar = mock_module.get_registrar()
    plain, numbered = [], []

    @registrar.on_change
    def changed(aor, event_type, contacts):
        plain.append(event_type)

    @registrar.on_change
    def changed_with_order(aor, event_type, contacts, sequence=None):
        numbered.append(sequence)

    registrar._fire_on_change("sip:201@example.com", "registered")
    registrar._fire_on_change("sip:201@example.com", "refreshed")

    assert plain == ["registered", "refreshed"], "a 3-argument handler still works"
    assert numbered[1] > numbered[0]
    assert isinstance(registrar.instance_epoch, str)


def test_the_registration_state_carries_a_rising_sequence():
    mock_module.reset()
    mock_module.install()
    seen = []

    @mock_module.get_registration().on_change
    def changed(aor, event_type, state):
        seen.append(state["sequence"])

    registration = mock_module.get_registration()
    registration.add("sip:trunk@example.net", "sip:registrar.example.net",
                     user="trunk", password="secret")
    registration.remove("sip:trunk@example.net")
    assert seen[1] > seen[0]
