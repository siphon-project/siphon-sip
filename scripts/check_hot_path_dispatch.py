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

Only `proxy.on_request` takes a method filter. `proxy.on_reply` and
`b2bua.on_invite` register unfiltered by construction, so there is no filtered
handler to move the awaits into. The same shape on those hooks is reported as a
note that states the cost and does not fail the check.
"""

import ast
import pathlib
import sys

# Decorators whose handlers run per message or per call.
PER_MESSAGE = {"on_request", "on_invite", "on_reply"}

# The subset that accepts a method filter, so the split this check prescribes
# can actually be written. The others have no filtered form.
FILTERABLE = {"on_request"}

SCRIPT_ROOTS = ["scripts"]


def _unfiltered_per_message(function):
    """`(namespace.hook, hook)` when `function` is an unfiltered per-message handler."""
    for decorator in function.decorator_list:
        # `@proxy.on_request` — an Attribute, so no call and no method filter.
        # `@proxy.on_request("REGISTER")` parses as a Call and is filtered.
        if isinstance(decorator, ast.Attribute) and decorator.attr in PER_MESSAGE:
            namespace = decorator.value.id if isinstance(decorator.value, ast.Name) else "?"
            return f"{namespace}.{decorator.attr}", decorator.attr
    return None


def _string_constants(node):
    """The strings in a literal or a tuple/list/set of literals, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        values = [_string_constants(element) for element in node.elts]
        if values and all(value is not None and len(value) == 1 for value in values):
            return set().union(*values)
    return None


def _is_method(node):
    return isinstance(node, ast.Attribute) and node.attr == "method"


def _method_names(test):
    """Methods a branch test confines its body to, or None if it is not a method test.

    Only a positive comparison against `.method` counts. A body type, a status
    code or any other condition contributes nothing to the method set: under
    `and` it narrows who reaches the body but is not a method, and under `or`
    it lets other methods in, so the branch is not method-gated at all.
    """
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        left, operator, right = test.left, test.ops[0], test.comparators[0]
        if isinstance(operator, ast.Eq):
            if _is_method(left):
                return _string_constants(right)
            if _is_method(right):
                return _string_constants(left)
        if isinstance(operator, ast.In) and _is_method(left):
            return _string_constants(right)
        return None
    if isinstance(test, ast.BoolOp):
        parts = [_method_names(value) for value in test.values]
        if isinstance(test.op, ast.And):
            known = [part for part in parts if part is not None]
            return set.intersection(*known) if known else None
        if all(part is not None for part in parts):
            return set().union(*parts)
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
        # e.g. `request.method == "REGISTER"`, `request.method in ("A", "B")`,
        # or `request.method == "INVITE" and reply.has_body("application/sdp")`.
        names = _method_names(node.test)
        if not names:
            continue
        inner = {id(n) for statement in node.body
                 for n in ast.walk(statement) if isinstance(n, ast.Await)}
        if inner:
            guarded |= inner
            methods |= names

    return methods if guarded == awaits else None


def check(path):
    """`(findings, notes)` for one script. Findings fail the check; notes do not."""
    findings, notes = [], []
    tree = ast.parse(path.read_text(), str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        matched = _unfiltered_per_message(node)
        if matched is None:
            continue
        decorator, hook = matched
        methods = _method_guarded_awaits(node)
        if not methods:
            continue
        joined = "|".join(sorted(methods))
        if hook in FILTERABLE:
            findings.append(
                f"{path}:{node.lineno}: `async def {node.name}` is an unfiltered "
                f"@{decorator} handler, but every await is under a "
                f"{joined} branch — move those into @{decorator}(\"{joined}\") "
                f"and leave this handler `def`, so the per-message path does not "
                f"pay asyncio dispatch")
        else:
            notes.append(
                f"{path}:{node.lineno}: `async def {node.name}` awaits only under a "
                f"{joined} branch, so every other message through @{decorator} "
                f"pays asyncio dispatch for nothing. @{decorator} takes no method "
                f"filter, so there is no handler to split this into; keep it "
                f"`async` if the awaited calls need an event loop")
    return findings, notes


SELF_TEST_FIXTURE = '''
from siphon import proxy, auth, registrar, rtpengine

DOMAIN = "example.com"


@proxy.on_request
async def needless(request):                     # FINDING REGISTER
    if request.method == "REGISTER":
        if not await auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)
        return
    request.relay()


@proxy.on_request
async def compound_branch(request):              # FINDING INVITE
    # The body-type test narrows the branch but is not a method, so it must
    # not leak into the suggested filter.
    if request.method == "INVITE" and request.has_body("application/sdp"):
        await rtpengine.offer(request)
    request.relay()


@proxy.on_request
async def method_tuple(request):                 # FINDING MESSAGE|SUBSCRIBE
    if request.method in ("SUBSCRIBE", "MESSAGE"):
        await auth.require_digest(request, realm=DOMAIN)
    request.relay()


@proxy.on_request
async def or_lets_everyone_in(request):
    # `or` with a non-method test reaches the await for any method.
    if request.method == "INVITE" or request.has_body("application/sdp"):
        await rtpengine.offer(request)
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


@proxy.on_reply
async def reply_has_no_filter(request, reply):   # NOTE
    # on_reply takes no method filter, so this is a note, not a finding.
    if request.method == "INVITE" and reply.has_body("application/sdp"):
        await rtpengine.answer(reply)
    reply.relay()

'''


def _fixture_labels():
    """`{line: expected filter}` for findings and `{line}` for notes."""
    findings, notes = {}, set()
    for number, line in enumerate(SELF_TEST_FIXTURE.splitlines(), start=1):
        if "# FINDING " in line:
            findings[number] = line.split("# FINDING ", 1)[1].strip()
        elif "# NOTE" in line:
            notes.add(number)
    return findings, notes


def self_test():
    """Check the matcher against the labelled fixture; return a process code."""
    import tempfile

    expected_findings, expected_notes = _fixture_labels()
    with tempfile.TemporaryDirectory() as directory:
        fixture = pathlib.Path(directory) / "fixture.py"
        fixture.write_text(SELF_TEST_FIXTURE)
        findings, notes = check(fixture)

    found = {int(finding.split(":")[1]): finding for finding in findings}
    noted = {int(note.split(":")[1]) for note in notes}
    problems = []
    for number in sorted(set(expected_findings) - set(found)):
        problems.append(f"missed a planted finding on fixture line {number}")
    for number in sorted(set(found) - set(expected_findings)):
        problems.append(f"flagged a handler that legitimately awaits, line {number}")
    for number, joined in sorted(expected_findings.items()):
        if number in found and f'("{joined}")' not in found[number]:
            problems.append(f"line {number} should suggest (\"{joined}\"): {found[number]}")
    for number in sorted(expected_notes - noted):
        problems.append(f"missed a planted note on fixture line {number}")
    for number in sorted(noted - expected_notes):
        problems.append(f"noted a handler that should be silent, line {number}")
    for note in notes:
        if '("' in note:
            problems.append(f"a note prescribes a filter its hook cannot take: {note}")

    if problems:
        print("FAIL: the hot-path matcher no longer agrees with its fixture.")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print(f"OK: matcher caught all {len(expected_findings)} planted findings and "
          f"{len(expected_notes)} notes, and nothing else.")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()

    given = [argument for argument in argv[1:] if not argument.startswith("--")]
    roots = [pathlib.Path(p) for p in given or SCRIPT_ROOTS]
    findings, notes, checked = [], [], 0
    for root in roots:
        paths = sorted(root.rglob("*.py")) if root.is_dir() else [root]
        for path in paths:
            checked += 1
            try:
                file_findings, file_notes = check(path)
            except SyntaxError as error:
                findings.append(f"{path}: could not parse: {error}")
                continue
            findings.extend(file_findings)
            notes.extend(file_notes)

    for note in notes:
        print(f"note: {note}")

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
