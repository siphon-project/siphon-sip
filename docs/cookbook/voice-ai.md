# Voice AI: answer a call with an AI over a WebSocket

A carrier call arrives, siphon answers it itself, and the caller's audio is
bridged to an external WebSocket media server — your agent. The AI never touches
RTP, jitter buffers or codecs: it reads and writes 16-bit linear PCM.

There is **no B leg**. The media engine anchors the call as a *single-leg*
session with the WebSocket server as the far side. That is what
`rtpengine.answer_local()` means, and it is why this is not a relay.

Requires `media.backend: siphon-rtp`. The WebSocket bridge is a native engine
extension — rtpengine and rtpproxy have no equivalent and fail the config load
rather than answering the call and bridging it nowhere.

## The shape

```python
@b2bua.on_invite
async def answer_with_ai(call):
    if not call.from_gateway("carriers"):
        call.reject(403, "Forbidden")
        return

    answer_sdp = await rtpengine.answer_local(
        call,
        profile="voice_ai",
        ws_uri="ws://127.0.0.1:9001/stream?call={call_id}",
    )
    if answer_sdp is None:
        return          # no encodable codec; auto-rejected 488

    call.answer(200, "OK", body=answer_sdp, content_type="application/sdp")
```

The full worked example is [`examples/voice_ai_b2bua.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/voice_ai_b2bua.py)
with its config in `examples/voice_ai_b2bua.yaml`.

`{call_id}` expands per call, so the AI can correlate the audio stream with the
call without a side channel. `{from_tag}`, `{from_user}` and `{to_user}` expand
too; an unknown placeholder is an error rather than a literal, so a typo cannot
reach the engine as a URI path segment.

## Bridge, not tee

Two different things stream audio to a WebSocket, and picking the wrong one is
the most common mistake here:

- **`ws_uri` — bridge / takeover.** The WebSocket server *becomes* the far side.
  There is no A↔B relay. This is the page you are reading.
- **`ws_tee` — additive copy.** The call relays normally *and* a copy streams
  out, leaving SIPREC and recording untouched. That is for transcription or
  compliance on an ordinary two-party call. See
  [media engines](../media-engines.md#websocket-audio-bridge-vs-tee).

## The profile

The built-in `voice_ai` profile sets everything except the endpoint:

```yaml
media:
  backend: siphon-rtp
  siphon_rtp:
    address: "127.0.0.1:8080"
  profiles:
    voice_ai:
      offer: &voice_ai_flags
        transport_protocol: "RTP/AVP"     # plain RTP toward the carrier
        ice: "remove"
        dtls: "off"
        replace: ["origin"]
        noise_suppression: true           # clean the uplink toward the AI
        echo_cancellation: true           # AI downlink is the echo reference
        ws_vad: true                      # turn boundaries without server-side VAD
        ws_barge_in: true                 # cut playout on the caller's speech edge
        ws_vad_hangover_ms: 300
      answer: *voice_ai_flags
```

`ws_uri` is deliberately unset in the built-in — there is no sensible default
endpoint — so it comes from your profile override or, as above, per call from the
script.

## The wire your server sees

The engine dials your server as a WebSocket client and speaks a small envelope:

- **Text frames** — `{"type": ..., "data": ...}`, camelCase fields. The first is
  `start`, announcing `streamId` and the audio `media` format.
- **Binary frames** — one raw little-endian L16 mono PCM frame per ptime. At
  8 kHz / 20 ms that is **320 bytes** (`sampleRate/1000 * ptime * 2`). Send binary
  frames back to play audio; no announcement needed.
- **`clear`** flushes queued playout for barge-in; the engine answers with a
  `mark` named `cleared`.
- **`stop`**, or closing the socket, ends the bridge. Deleting the call also
  tears it down.

A reference server lives in the engine repo at
[`examples/voice-ai/server.py`](https://github.com/siphon-project/siphon-rtp/blob/main/examples/voice-ai/server.py).
It echoes the caller back, which is the quickest way to prove the whole path.
The protocol reference is
[siphon-rtp's voice-AI cookbook](https://github.com/siphon-project/siphon-rtp/blob/main/docs/cookbook/voice-ai.md).

## Running it end to end

```sh
# 1. the AI side (echo server proves the path; swap in your agent later)
pip install websockets
python3 siphon-rtp/examples/voice-ai/server.py      # ws://127.0.0.1:9001/stream

# 2. the media engine
siphon-rtp --control 127.0.0.1:8080 --relay-bind-ip 127.0.0.1

# 3. siphon
siphon -c examples/voice_ai_b2bua.yaml
```

Then place a call from a source inside the `carriers` gateway group. With the
echo server, the caller hears themselves back with a couple of frames of delay.

What a working run looks like:

```
# the AI server
connection open
start ws-<call-id> {'encoding': 'L16', 'sampleRate': 8000, 'channels': 1,
                    'bitDepth': 16, 'endianness': 'little', 'ptime': 20}
control speech_started {'streamId': 'ws-<call-id>'}

# the engine
websocket bridge attached to the single-leg answer  role="uas_local_ws"
call finished  pipeline=Ws  near_codec="PCMU"  far_codec="-"
```

`pipeline=Ws` and `far_codec="-"` are the two to check. They mean the leg is
bridged to the socket and there is no far SIP party — if you see `pipeline=Media`
and a real `far_codec`, the bridge did not attach and the audio you are hearing
is coming from somewhere else.

!!! warning "Returned audio is not proof on its own"
    A single-leg call can generate audio locally, so hearing *something* back
    does not mean the bridge works. Check the WebSocket server's own log for the
    `start` envelope. That is the only signal that says your server is in the
    path.

## Requirements

The bridge needs `siphon-rtp` **0.1.5 or later** on both sides: siphon's pinned
`siphon-rtp-proto`, and the running engine. Earlier engine builds accept
`ws_uri` on `answer_local` and silently never dial it.

## Handing the caller to a human

A cold transfer is an in-dialog REFER on the A dialog. On a call siphon answered
itself there is one way to send it:

```python
@rtpengine.on_dtmf
def on_digit(call_id, from_tag, digit, duration_ms, volume):
    if digit == "0":
        b2bua.refer(call_id, "sip:agent@pbx.example.com")
```

**Use the imperative `b2bua.refer(call_id, ...)`, not `call.refer()`.** That is
not a style preference:

- `@b2bua.on_answer` never fires for a call siphon answered itself — that hook is
  a *B leg's* 2xx arriving, and there is no B leg.
- `call.refer()` is deliberately a no-op from `@b2bua.on_invite`, because the
  dialog is not confirmed until the 2xx has gone out.

So on a single-leg call the transfer has to come from an event context — DTMF, a
timer, an external controller — and those only have the SIP Call-ID, which is
exactly what the imperative verb takes.

### When the carrier challenges the REFER

Plenty of trunks answer an in-dialog REFER with a 407.
Give the call credentials and siphon retries with digest:

```python
@b2bua.on_invite
async def answer_with_ai(call):
    call.set_credentials("trunk-user", "trunk-secret")
    ...
```

Set them before the transfer can fire — the retry reads them off the call. The
retry is a new transaction on the same dialog (RFC 3261 §22.2) and is capped, so
a trunk that challenges unconditionally cannot loop. Without credentials the
challenge is logged at WARN and the transfer fails rather than retrying blind.

## Where the policy lives

The example above keeps everything in the in-process script. To drive the same
call from an external application instead — the ARI/ESL model — hand it over:

```python
call.handover("voice-ai-app", answer=True,
              ws_uri="ws://127.0.0.1:9001/stream?call={call_id}")
```

`answer=True` answers and anchors the media *before* handing over, so the
controller inherits a connected channel. The audio still goes directly between
the engine and your WebSocket server; the control plane carries call control
only. See [`examples/voice_ai_control.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/voice_ai_control.py)
and the [control-plane reference](../reference/control-plane.md).

Note that prompt playback and DTMF are not control-plane verbs yet, so an app
that needs them reads DTMF in-process via `@rtpengine.on_dtmf` or handles it
inside the AI over the audio stream.
