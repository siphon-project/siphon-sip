#!/usr/bin/env python3
"""Fail if a shipped script makes a per-message handler `async def` needlessly.

An `async def` handler is dispatched through an asyncio driver; a `def` handler
runs on the synchronous worker pool. For a handler that actually awaits, the
driver is what keeps one slow call from blocking others. For a handler that
reaches no `await` on the path a message actually takes, it is pure overhead —
a coroutine built, handed across threads, and resolved, per message.

Measured on `MODE=proxy TRANSPORT=udp scale_test.sh 40000 10000 8`: the shipped
`proxy_default.py` with one `async def` catch-all peaked at 645 % CPU; the same
binary with the REGISTER branch split into its own `async` handler and the call
path left synchronous peaked at 297 %, matching the pre-1.10 floor of 286 %.
Throughput was identical, so nothing but CPU headroom was being spent.

What this flags: an **unfiltered** per-message handler declared `async def`
whose every `await` sits inside a single-method branch. Those awaits belong in a
method-filtered handler — `@proxy.on_request("REGISTER")` — leaving the
unfiltered handler synchronous. `proxy_request_handlers` matches an unfiltered
handler for every method and a filtered one only for its own, so the split
changes no behaviour: the filtered method reaches both handlers, every other
method reaches only the synchronous one.

What this does NOT flag: a handler that awaits on the path every message takes.
There the driver is doing its job, and making it synchronous would block the
pool instead.
"""

import ast
import pathlib
import sys

# Decorators whose handlers run per message or per call.
PER_MESSAGE = {"on_request", "on_invite", "on_reply"}

SCRIPT_ROOTS = ["scripts"]


def _unfiltered_per_message(function):
    """The decorator name when `function` is an unfiltered per-message handler."""
    for decorator in function.decorator_list:
        # `@proxy.on_request` — an Attribute, so no call and no method filter.
        # `@proxy.on_request("REGISTER")` parses as a Call and is filtered.
        if isinstance(decorator, ast.Attribute) and decorator.attr in PER_MESSAGE:
            namespace = decorator.value.id if isinstance(decorator.value, ast.Name) else "?"
            return f"{namespace}.{decorator.attr}"
    return None


def _method_guarded_awaits(function):
    """Methods whose branches contain every `await` in `function`.

    Returns the set of method names when all awaits are confined to branches
    testing a specific method, else None (awaits are on the common path).
    """
    awaits = {id(node) for node in ast.walk(function) if isinstance(node, ast.Await)}
    if not awaits:
        return set()

    methods, guarded = set(), set()
    for node in ast.walk(function):
        if not isinstance(node, ast.If):
            continue
        test = ast.unparse(node.test)
        if ".method" not in test:
            continue
        # String literals compared against in the branch test, e.g.
        # `request.method == "REGISTER"` or `request.method in ("A", "B")`.
        names = {n.value for n in ast.walk(node.test)
                 if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        if not names:
            continue
        inner = {id(n) for statement in node.body
                 for n in ast.walk(statement) if isinstance(n, ast.Await)}
        if inner:
            guarded |= inner
            methods |= names

    return methods if guarded == awaits else None


def check(path):
    findings = []
    tree = ast.parse(path.read_text(), str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        decorator = _unfiltered_per_message(node)
        if decorator is None:
            continue
        methods = _method_guarded_awaits(node)
        if methods:
            joined = "|".join(sorted(methods))
            findings.append(
                f"{path}:{node.lineno}: `async def {node.name}` is an unfiltered "
                f"@{decorator} handler, but every await is under a "
                f"{joined} branch — move those into @{decorator}(\"{joined}\") "
                f"and leave this handler `def`, so the per-message path does not "
                f"pay asyncio dispatch")
    return findings


SELF_TEST_FIXTURE = '''
from siphon import proxy, auth, registrar

DOMAIN = "example.com"


@proxy.on_request
async def needless(request):                     # FINDING
    if request.method == "REGISTER":
        if not await auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)
        return
    request.relay()


@proxy.on_request
async def genuinely_awaits(request):
    # Awaits on the path every message takes, so the driver is earning its cost.
    if not await auth.require_digest(request, realm=DOMAIN):
        return
    request.relay()


@proxy.on_request("REGISTER")
async def filtered_is_fine(request):
    if not await auth.require_digest(request, realm=DOMAIN):
        return
    registrar.save(request)


@proxy.on_request
def already_sync(request):
    request.relay()
'''


def self_test():
    """Check the matcher against the labelled fixture; return a process code."""
    import tempfile

    expected = {number + 1 for number, line
                in enumerate(SELF_TEST_FIXTURE.splitlines())
                if "# FINDING" in line}
    with tempfile.TemporaryDirectory() as directory:
        fixture = pathlib.Path(directory) / "fixture.py"
        fixture.write_text(SELF_TEST_FIXTURE)
        found = {int(finding.split(":")[1]) for finding in check(fixture)}

    missed, spurious = sorted(expected - found), sorted(found - expected)
    if missed or spurious:
        print("FAIL: the hot-path matcher no longer agrees with its fixture.")
        for number in missed:
            print(f"  missed a planted finding on fixture line {number}")
        for number in spurious:
            print(f"  flagged a handler that legitimately awaits, line {number}")
        return 1
    print(f"OK: matcher caught all {len(expected)} planted findings and nothing else.")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()

    given = [argument for argument in argv[1:] if not argument.startswith("--")]
    roots = [pathlib.Path(p) for p in given or SCRIPT_ROOTS]
    findings, checked = [], 0
    for root in roots:
        paths = sorted(root.rglob("*.py")) if root.is_dir() else [root]
        for path in paths:
            checked += 1
            try:
                findings.extend(check(path))
            except SyntaxError as error:
                findings.append(f"{path}: could not parse: {error}")

    if findings:
        print(f"FAIL: {len(findings)} per-message handler(s) async without need:")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print(f"OK: no per-message handler pays asyncio dispatch needlessly "
          f"({checked} files checked).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
