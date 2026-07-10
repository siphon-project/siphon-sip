# IMS control

The namespaces that make SIPhon an IMS core: iFC evaluation (`isc`), 5G SBI /
N5 policy authorization and Nbsf discovery (`sbi`), SIP presence (`presence`),
lawful intercept (`li`), and the Session Recording Server hooks (`srs`).

## `isc` namespace

Initial Filter Criteria evaluation (3GPP TS 29.228 / IMS Service Control).

::: siphon_sdk.mock_module.MockIsc

## `sbi` namespace

5G Service-Based Interface — N5/Npcf policy authorization plus Nbsf_Management
PCF discovery.

::: siphon_sdk.mock_module.MockSbi

### `BsfError`

Raised by `sbi.discover_pcf_binding(...)` when the BSF is unhealthy.

::: siphon_sdk.mock_module.BsfError

## `presence` namespace

SIP presence document publish/lookup and subscription tracking (RFC 3856 /
6665).

::: siphon_sdk.mock_module.MockPresence

## `li` namespace

Lawful intercept (ETSI X1/X2/X3) and SIPREC recording triggers.

::: siphon_sdk.mock_module.MockLi

## `srs` namespace

Session Recording Server acceptance hooks (RFC 7866 SIPREC).

::: siphon_sdk.mock_module.MockSrs

### `SrsSession`

A completed recording session.

::: siphon_sdk.srs.SrsSession

### `RecordingMetadata`

Parsed RFC 7866 recording metadata from a SIPREC INVITE.

::: siphon_sdk.srs.RecordingMetadata

### `SrsParticipant`

::: siphon_sdk.srs.SrsParticipant

### `SrsStreamInfo`

::: siphon_sdk.srs.SrsStreamInfo
