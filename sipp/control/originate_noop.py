"""No-op script for the `originate` acceptance test.

The control application places every call over the control rail, so nothing here
routes anything. It exists because a running siphon loads a script, and it is
deliberately empty so the test proves the control-plane path and nothing else.
"""

from siphon import log

log.info("originate acceptance test: no in-process routing, control app drives")
