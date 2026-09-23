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
async def subscribe(request):
    expires = int(request.get_header("Expires") or "30")
    handle = proxy.subscribe_state.accept(request, expires=expires)
    if handle is None:
        return
    body = "Messages-Waiting: no\r\nVoice-Message: 0/0\r\n"
    # The lock is a threading.Lock, so it is released before awaiting: holding
    # it across an await lets another coroutine on the same driver loop block
    # on it and take the whole loop down with it.
    with _lock:
        if expires == 0:
            _watchers.pop(handle.id, None)
        elif request.get_header("X-No-Change") != "yes":
            _watchers.setdefault(handle.id, False)
    if expires == 0:
        await handle.terminate(reason="deactivated", body=body, content_type=_type)
    else:
        await handle.notify(body=body, content_type=_type)


@timer.every(seconds=1, name="notify_mailbox_change")
async def mailbox_change():
    with _lock:
        pending = [i for i, notified in _watchers.items() if not notified]
    for identifier in pending:
        handle = await proxy.subscribe_state.get(identifier)
        drop = handle is None or handle.expires == 0
        if not drop:
            await handle.notify(
                body="Messages-Waiting: yes\r\nVoice-Message: 1/0\r\n",
                content_type=_type,
            )
        with _lock:
            if drop:
                _watchers.pop(identifier, None)
            else:
                _watchers[identifier] = True
