#!/usr/bin/env python3
"""Fail if a shipped script calls an awaitable siphon API without `await`.

A forgotten `await` on one of these does not raise: the call returns a
coroutine, which is truthy and never runs.  `if not auth.require_www_digest(...)`
then takes the authenticated branch and no challenge is ever sent, and
`diameter.rx_str(session)` returns a coroutine the logger happily formats while
no Diameter message leaves the process.  Both read as working code.

So this walks the AST instead of grepping: a call is a finding only when its
Call node is neither the operand of an `Await` nor handed to `asyncio`'s
scheduling helpers.  That is what separates `await x.notify()` from `x.notify()`
from `asyncio.create_task(x.notify())`, none of which a regex can tell apart.

The method sets below are maintained by hand against `src/script/api/`.  Derive
them with: grep for `script::awaitable(` / `script::ready(` and map each hit to
its enclosing `fn` — an awaitable pymethod is exactly one that reaches those,
plus the few that call `pyo3_async_runtimes::tokio::future_into_py` directly.

Two scopes, both unexecuted by any test:

* default — the shipped handler scripts, which only a live node runs.
* `--docs` — ```python blocks under `docs/` and in the README, which is the
  bigger source, because an author copies a snippet rather than deriving it.

`sdk/` is deliberately out of scope: the SDK's own tests drive coroutines through
`asyncio.run`, so a missed `await` there fails in the SDK suite instead of in
production.  Note that an awaitable mock is a plain `def` returning an inner
coroutine, the same shape a pymethod has, so `iscoroutinefunction` is the wrong
thing to assert on in either place.
"""

import ast
import pathlib
import re
import sys

# Awaitable methods reached through a namespace imported from `siphon`.
NAMESPACE_AWAITABLE = {
    "diameter": {
        "cx_uar", "cx_sar", "cx_lir",
        "rx_aar", "rx_str",
        "sh_udr", "sh_pur", "sh_snr",
        "rf_acr_start", "rf_acr_interim", "rf_acr_stop", "rf_acr_event",
        "s6a_air", "s6a_ulr", "s6a_purge_ue",
        "s6c_srr", "s6c_rsr", "sgd_tfr",
        "send_request",
    },
    "auth": {
        "require_digest", "require_www_digest", "require_proxy_digest",
        "require_ims_digest", "verify_digest",
    },
    "presence": {"notify", "terminate"},
    "sbi": {
        "discover_pcf_binding", "create_session", "update_session",
        "delete_session",
    },
    "proxy": {"send_request"},
}

# Awaitable methods on `<namespace>.subscribe_state`.
SUBSCRIBE_STATE_AWAITABLE = {"get", "send"}

# Sync methods on `<namespace>.subscribe_state` that hand back a handle.  A
# variable bound from one of these is a SubscribeHandle, whose own awaitable
# methods we then police.
SUBSCRIBE_STATE_HANDLE_SOURCES = {"accept", "create", "get"}
HANDLE_AWAITABLE = {"notify", "terminate", "refresh"}

# Awaitable methods whose receiver is a per-request object rather than a
# namespace, and whose name collides with nothing else in these trees.
UNAMBIGUOUS_AWAITABLE = {"forward_to"}

# A call passed to one of these is scheduled rather than abandoned.
SCHEDULERS = {"create_task", "ensure_future", "gather", "wait_for", "shield", "wait"}


def _attribute_path(node):
    """Dotted source text of an attribute chain, or None if not a plain chain."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _siphon_names(tree):
    """Names bound by `from siphon import ...` in this module."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "siphon":
            names.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "siphon":
                    names.add(alias.asname or alias.name)
    return names


def _excused(tree):
    """Call nodes that are awaited, or handed to an asyncio scheduler."""
    excused = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
            excused.add(id(node.value))
        if isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else (
                node.func.id if isinstance(node.func, ast.Name) else None)
            if name in SCHEDULERS:
                for argument in [*node.args, *(k.value for k in node.keywords)]:
                    if isinstance(argument, ast.Call):
                        excused.add(id(argument))
    return excused


def _handle_variables(tree, siphon):
    """Local names bound from a subscribe_state call that returns a handle."""
    handles = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if isinstance(value, ast.Await):
            value = value.value
        if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
            continue
        if value.func.attr not in SUBSCRIBE_STATE_HANDLE_SOURCES:
            continue
        path = _attribute_path(value.func)
        if path is None or "subscribe_state" not in path.split(".")[:-1]:
            continue
        if path.split(".")[0] not in siphon:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        handles.update(t.id for t in targets if isinstance(t, ast.Name))
    return handles


def _scan(tree, siphon, label, line_offset=0):
    """Findings in one parsed tree, attributed to `label` at `line_offset`."""
    excused = _excused(tree)
    handles = _handle_variables(tree, siphon)
    findings = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or id(node) in excused:
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        method = node.func.attr
        receiver = node.func.value
        path_text = _attribute_path(node.func)

        what = None
        if isinstance(receiver, ast.Name) and receiver.id in siphon:
            if method in NAMESPACE_AWAITABLE.get(receiver.id, ()):
                what = f"{receiver.id}.{method}()"
        elif (isinstance(receiver, ast.Attribute)
              and receiver.attr == "subscribe_state"
              and method in SUBSCRIBE_STATE_AWAITABLE
              and path_text and path_text.split(".")[0] in siphon):
            what = f"{path_text}()"
        elif isinstance(receiver, ast.Name) and receiver.id in handles:
            if method in HANDLE_AWAITABLE:
                what = f"{receiver.id}.{method}()  [SubscribeHandle]"
        elif method in UNAMBIGUOUS_AWAITABLE:
            what = f"{method}()"

        if what:
            line = node.lineno + line_offset
            findings.append(f"{label}:{line}: {what} is awaitable but not awaited")
    return findings


def check(path):
    """Findings in a shipped script, whose siphon names are resolved by import."""
    tree = ast.parse(path.read_text(), str(path))
    return _scan(tree, _siphon_names(tree), str(path))


# ```python blocks in the docs are the other place this bug spreads from, and the
# bigger one: an author copies the snippet rather than deriving it.  Blocks are
# fragments, so the namespaces are assumed bound instead of resolved by import,
# and a fragment that will not parse standalone is skipped rather than failed.
DOC_BLOCK = re.compile(r"```py(?:thon)?\n(.*?)```", re.DOTALL)
ASSUMED_DOC_NAMESPACES = set(NAMESPACE_AWAITABLE) | {"registrar", "cache"}


def check_doc(path):
    """Findings across every parseable python block in one markdown file."""
    text = path.read_text()
    findings = []
    for match in DOC_BLOCK.finditer(text):
        # Line of the block's first code line: newlines before the fence, plus
        # one to reach the fence itself and one more to step past it.
        offset = text[: match.start()].count("\n") + 1
        try:
            tree = ast.parse(match.group(1))
        except SyntaxError:
            continue
        findings.extend(_scan(tree, ASSUMED_DOC_NAMESPACES, str(path), offset))
    return findings


# A gate that stops matching anything passes silently, which is the way a check
# like this actually fails.  `--self-test` runs the matcher over a fixture whose
# every line is labelled, and fails unless the findings are exactly the lines
# marked FINDING — so a broken matcher is caught by CI rather than by a release.
SELF_TEST_FIXTURE = """
import asyncio
from siphon import proxy, auth, diameter, presence, sbi


@proxy.on_request("REGISTER")
async def handler(request, socket, process):
    if not auth.require_www_digest(request, realm="x"):    # FINDING
        return
    await auth.require_proxy_digest(request, realm="x")
    handle = proxy.subscribe_state.create(request)
    handle.notify(body="x")                               # FINDING
    await handle.terminate()
    asyncio.create_task(handle.refresh(60))
    later = await proxy.subscribe_state.get("id")
    proxy.subscribe_state.get("id")                       # FINDING
    diameter.cx_uar("sip:a@b")                            # FINDING
    sbi.delete_session("s")                               # FINDING
    presence.notify("a")                                  # FINDING
    socket.send(b"x")
    process.terminate()
    later.notify(body="y")                                # FINDING
    await proxy.send_request("OPTIONS", "sip:a@b")
"""


def self_test():
    """Check the matcher against the labelled fixture; return a process code."""
    import tempfile

    expected = {
        number
        for number, line in enumerate(SELF_TEST_FIXTURE.splitlines(), start=0)
        if "# FINDING" in line
    }
    # `splitlines()` is 0-based over a fixture whose leading newline `ast`
    # counts as line 1, so the enumeration starts one behind it.
    expected = {number + 1 for number in expected}
    with tempfile.TemporaryDirectory() as directory:
        fixture = pathlib.Path(directory) / "fixture.py"
        fixture.write_text(SELF_TEST_FIXTURE)
        found = {int(finding.split(":")[1]) for finding in check(fixture)}

    missed = sorted(expected - found)
    spurious = sorted(found - expected)
    if missed or spurious:
        print("FAIL: the awaited-API matcher no longer agrees with its fixture.")
        for number in missed:
            print(f"  missed a planted finding on fixture line {number}")
        for number in spurious:
            print(f"  flagged a legitimate call on fixture line {number}")
        return 1
    print(f"OK: matcher caught all {len(expected)} planted findings and nothing else.")
    return 0


SCRIPT_ROOTS = ["scripts", "examples", "sipp"]
DOC_ROOTS = ["docs", "README.md"]


def main(argv):
    if "--self-test" in argv:
        return self_test()

    docs = "--docs" in argv
    given = [argument for argument in argv[1:] if not argument.startswith("--")]
    roots = [pathlib.Path(p) for p in given or (DOC_ROOTS if docs else SCRIPT_ROOTS)]

    findings, checked = [], 0
    for root in roots:
        if docs:
            paths = sorted(root.rglob("*.md")) if root.is_dir() else [root]
        else:
            paths = sorted(root.rglob("*.py"))
        for path in paths:
            checked += 1
            try:
                findings.extend(check_doc(path) if docs else check(path))
            except SyntaxError as error:
                findings.append(f"{path}: could not parse: {error}")

    if findings:
        print(f"FAIL: {len(findings)} awaitable call(s) missing `await`:")
        for finding in findings:
            print(f"  {finding}")
        print("\nAn un-awaited call returns a truthy coroutine and never runs.")
        return 1
    print(f"OK: every awaitable siphon call is awaited ({checked} files checked).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
