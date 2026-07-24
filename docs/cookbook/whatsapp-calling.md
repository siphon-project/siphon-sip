# WhatsApp calling (Business Calling API)

The [WhatsApp Business Calling API](https://developers.facebook.com/documentation/business-messaging/whatsapp/calling)
is SIP-native: Meta terminates and originates voice calls as ordinary SIP over
TLS to `wa.meta.vc`, with OPUS media over SRTP. That makes SIPhon a natural
gateway between WhatsApp and your own SIP/IMS network, in both directions, with
no new protocol code — it is a specialised TLS trunk plus a B2BUA routing script.

```
WhatsApp  <-- SIP/TLS + SRTP -->  SIPhon  <-- SIP + RTP -->  internal PBX / trunk
```

The runnable example is [`examples/whatsapp_calling.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/whatsapp_calling.py)
and [`examples/whatsapp_calling.yaml`](https://github.com/siphon-project/siphon-sip/blob/main/examples/whatsapp_calling.yaml).

!!! note "Messaging is a separate integration"
    WhatsApp also has a Cloud API for **text / media / template messages**. That
    is plain HTTP (Graph API + webhooks), not SIP, so it lives with the HTTP
    addon: see the **WhatsApp Cloud API** recipe in the
    [siphon-http cookbook](https://http.siphon-sip.org/cookbook/whatsapp-cloud-api/).

## What Meta requires

A few WhatsApp constraints shape the config; get them wrong and calls fail:

- **TLS is mandatory and server-auth only.** Meta presents a server certificate
  for `wa.meta.vc` and does **not** do mutual TLS — it neither sends nor requests
  a client certificate. So, unlike a Microsoft Teams trunk, there is **no
  `tls.client_certificate`**. Meta connects to the public FQDN you register as
  the number's SIP server, so that FQDN must be your `advertised_address` and the
  SAN on your server cert.
- **OPUS only.** WhatsApp offers/accepts OPUS (48 kHz) plus `telephone-event`
  (RFC 4733 DTMF). This gateway anchors and relays media; it does not transcode,
  so the internal leg must also speak OPUS. Bridging to a G.711/AMR-only endpoint
  needs rtpengine transcoding, which is out of scope here.
- **No re-INVITE toward Meta.** A re-INVITE fails the call, so the example ships
  **without** a `session_timer:` block (a `refresher=uac` session timer would
  send Meta a refresh re-INVITE). Do not enable session timers, hold, or a
  transfer-driven media re-anchor toward the WhatsApp leg.
- **No PSTN breakout.** Meta's terms forbid bridging WhatsApp calls to the PSTN;
  keep the internal leg on-net VoIP/SIP.
- **Trust via TLS + digest.** Outbound calls authenticate to Meta with SIP
  digest, and you can challenge inbound ones. Meta does **not** do mutual TLS, so
  do not trust an application-layer header (like `X-FB-External-Domain`) as an
  auth signal — any peer reaching the TLS port could forge it. The source IP, by
  contrast, is handshake-verified on TLS; Meta sources from a wide published set
  of ranges, so the `whatsapp` gateway group lists them under `source_networks`
  and the script keys direction on `call.from_gateway("whatsapp")`.

## SRTP keying: SDES or DTLS

WhatsApp keys SRTP per phone number, one of two ways:

- **SDES** — the crypto key travels in the SDP over the (secure) TLS signalling.
  This is a plain SRTP trunk, so SIPhon's built-in `srtp_to_rtp` /`rtp_to_srtp`
  profiles already do the job. Simplest to bring up; the example defaults to it.
- **DTLS-SRTP** — a DTLS handshake keys the media (WebRTC-style, with ICE). The
  example ships `whatsapp_dtls_in` / `whatsapp_dtls_out` profiles for this, based
  on the built-in `wss_to_rtp` WebRTC profile. rtpengine terminates DTLS on the
  WhatsApp side and bridges to the internal RTP leg — there is no opaque DTLS
  pass-through when anchoring. **Validate the DTLS role / ICE against your own
  number before production**; the correct role can depend on Meta's offer.

Select the mode with `WHATSAPP_MEDIA_MODE=sdes` (default) or `=dtls`.

## The routing script

Direction is keyed on `call.from_gateway("whatsapp")` — the source IP, which on
the inbound TLS connection is handshake-verified (unlike the spoofable
`X-FB-External-Domain` header, since Meta does not do mutual TLS). The `whatsapp`
group's `source_networks` carries Meta's published ranges so the match is stable
regardless of DNS. Inbound calls bridge to the internal gateway; outbound calls
authenticate to Meta and dial `wa.meta.vc` over TLS.

```python
from siphon import b2bua, gateway, rtpengine, log

@b2bua.on_invite
async def route(call):
    if call.from_gateway("whatsapp"):
        # WhatsApp -> internal: a WhatsApp user is calling the business number.
        destination = gateway.select("internal")
        await rtpengine.offer(call, profile="srtp_to_rtp")
        call.dial(destination.uri)
    else:
        # internal -> WhatsApp: dial an E.164 over the TLS trunk. From is the
        # business number, which is also the digest username Meta cross-checks;
        # SIPhon answers Meta's 407 with Proxy-Authorization automatically.
        e164 = call.ruri.user
        call.set_from_user(BUSINESS_NUMBER)
        call.set_credentials(BUSINESS_NUMBER, SIP_PASSWORD)
        await rtpengine.offer(call, profile="rtp_to_srtp")
        call.dial(f"sip:{e164}@wa.meta.vc:5061;transport=tls")
```

`call.set_credentials()` is all that outbound digest needs — Meta answers the
first INVITE with `407 Proxy Authentication Required` and SIPhon resends with the
`Proxy-Authorization` header. The per-number password comes from Meta: GET the
phone number's settings with `include_sip_credentials=true`.

For inbound calls you can additionally challenge Meta with digest (recommended by
Meta for defence in depth); on a media-anchored B2BUA, trust is already
established by the TLS connection.

## Provisioning checklist (Meta side)

1. Configure a SIP server for the business phone number pointing at your gateway
   FQDN on port 5061 over TLS.
2. Retrieve the number's SIP digest password (`include_sip_credentials=true`) and
   pass it to the script as `$WHATSAPP_SIP_PASSWORD`, with the E.164 business
   number as `$WHATSAPP_BUSINESS_NUMBER`.
3. Choose the SRTP keying mode (SDES or DTLS) to match `WHATSAPP_MEDIA_MODE`.
4. Point a publicly-trusted TLS certificate (SAN = your gateway FQDN) at the
   `tls:` block, and put that FQDN in `advertised_address`.

Run it:

```bash
siphon -c examples/whatsapp_calling.yaml
```
