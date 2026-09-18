"""Package policy fixture; the engine owns dialog and transport state."""
from siphon import proxy, timer
from threading import Lock

_watchers = {}
_lock = Lock()
_type = "application/simple-message-summary"


@proxy.on_request("OPTIONS")
def ready(request):
    request.reply(200, "OK")


@proxy.on_request("SUBSCRIBE")
def subscribe(request):
    expires = int(request.get_header("Expires") or "30")
    handle = proxy.subscribe_state.accept(request, expires=expires)
    if handle is None:
        return
    body = "Messages-Waiting: no\r\nVoice-Message: 0/0\r\n"
    with _lock:
        if expires == 0:
            _watchers.pop(handle.id, None)
            handle.terminate(reason="deactivated", body=body, content_type=_type)
        else:
            handle.notify(body=body, content_type=_type)
            if request.get_header("X-No-Change") != "yes":
                _watchers.setdefault(handle.id, False)


@timer.every(seconds=1, name="notify_mailbox_change")
def mailbox_change():
    with _lock:
        for identifier, notified in list(_watchers.items()):
            if notified:
                continue
            handle = proxy.subscribe_state.get(identifier)
            if handle is None:
                del _watchers[identifier]
                continue
            if handle.expires == 0:
                del _watchers[identifier]
                continue
            handle.notify(body="Messages-Waiting: yes\r\nVoice-Message: 1/0\r\n", content_type=_type)
            _watchers[identifier] = True
