# Migrating to 1.15.0

1.15.0 numbers the Node-Functionality AVP (code 862) as TS 32.299 §7.2.113
does. Values 0 to 7 (S-CSCF to IBCF) are unchanged. Above that siphon had its
own table, so records from an E-CSCF, an ATCF or a node configured as `mmtel`
went out as another node. No `siphon.yaml` key stops working.

| name | sent before | sent now |
|---|---|---|
| `ecscf` | 9 (P-GW) | 11 |
| `atcf` | 10 (HSGW) | 15 |
| `mmtel` | 11 (E-CSCF) | 6 (AS) |
| `scscf-restore`, `tpf`, `atgw` | 8, 12, 13 | not a value |
| `sgw`, `pgw`, `hsgw`, `mme`, `trf`, `tf`, `proxy`, `epdg`, `tdf`, `twag`, `scef`, `iwk-scef` | not accepted | 8 to 21 |

## siphon.yaml

`rf.node_functionality` and `ro.node_functionality` set to `scscf-restore`,
`tpf` or `atgw` still load. siphon logs that the name is not recognised and
leaves the AVP out of the records, as it always did for an unknown name. Pick
the function the node has from the table, `as` for an application server.

## Python scripting API

`node_functionality="scscf-restore"`, `"tpf"` and `"atgw"` on
`diameter.ro_ccr_*`, `diameter.rf_acr_*` and `diameter.ro_session` raise
`ValueError`. `"mmtel"` is still accepted and sends 6.

## Rust library

`NodeFunctionality::SCscfRestore`, `Mmtel`, `Tpf` and `Atgw` are removed.
`Ecscf` is 11 and `Atcf` 15. `SGw`, `PGw`, `Hsgw`, `Mme`, `Trf`, `Tf`,
`ProxyFunction`, `Epdg`, `Tdf`, `Twag`, `Scef` and `IwkScef` are new.
