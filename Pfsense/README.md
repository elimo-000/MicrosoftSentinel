# Netgate pfSense — ASIM Network Session parser (Custom)

Normalizes pfSense `filterlog` traffic records — ingested as CEF via the
`CommonSecurityLog` table — to the ASIM Network Session schema (v0.2.7).
Also includes the rsyslog config that turns pfSense's native filterlog
format into the CEF fields this parser expects.

## Files

| File | Purpose |
|---|---|
| `vimNetworkSessionPfsenseCustom.kql` / `.json` | Parameterized filtering parser over `CommonSecurityLog` (`DeviceVendor == "NETGATE"`, `DeviceProduct == "pfsense"`, `DeviceEventClassID == "filterlog"`). |
| `ASimNetworkSessionPfsenseCustom.kql` / `.json` | Parameter-less wrapper, needed alongside the filtering parser per Microsoft's ASIM guidance ("add both a filtering custom parser and a parameter-less custom parser"), for pickup by the non-parametrized `ASimNetworkSession` unifying parser. |
| `PFsense_Rsyslog_Conf_CEF_Sentinel_Schema.conf` | Current rsyslog template/ruleset: reshapes pfSense's raw `filterlog` line into CEF, including full ICMP/ICMPv6 field breakdown, and forwards to the local AMA collector port. Also carries a sample nginx-access-log CEF template. |
| `PFsense_Rsyslog_Conf_CEF_Sentinel_Schema_OLD.conf` | Superseded version, kept for reference/rollback. See "Fixes over the OLD config" below for what changed. |

## Parser highlights (`vimNetworkSessionPfsenseCustom`)

- **IPv4/IPv6 source & destination**: falls back from `SourceIP`/`DestinationIP`
  to the CEF custom IPv6 fields using `isnotempty()`, not `coalesce()` —
  pfSense's rsyslog template always emits `src=`/`dst=` even on IPv6 rows,
  so those columns arrive as an *empty string*, not `null`, and `coalesce()`
  would never fall through to the real IPv6 value.
- **`DvcOriginalAction`** is populated from the raw `DeviceAction`, not from
  `EventOriginalResultDetails` (a separate ASIM concept that feeds
  `EventResultDetails`).
- **`NetworkRuleName`** uses pf's `trackerid` (extracted from
  `AdditionalExtensions`), not the rule's ordinal position — the tracker ID
  stays stable if rules get reordered, so it's the safer field to key
  hunts/detections on.
- **`NetworkBytes`** is a single total per logged packet: pf logs one packet
  per line, one direction at a time (`in=` or `out=`, never both), so there's
  no reliable per-session Src/Dst byte split available.
- **`EventResult`/`EventSeverity`** are derived from the normalized
  `DvcAction`, not hardcoded to `Success` — a prior version of this logic
  marked every row (including blocked/denied traffic) as `Success`.

## Fixes over the OLD config

- **ICMP field coverage**: `needfrag` / `tstamp` / `tstampreply` messages
  each carry more fields than pf's other ICMP types. The OLD config routed
  anything outside `request`/`reply`/`unreachproto`/`unreachport` into a
  single generic `icmptext` catch-all, silently dropping the MTU on
  `needfrag` and the extra timestamp fields on `tstamp`/`tstampreply`.
- **`unreachableport`** was being captured by the OLD ruleset but never
  actually emitted by its CEF template — the value was silently discarded.
  Fixed by adding `unreachableport=` to the template.
- **ICMPv6 handling** was missing entirely in the OLD config — ICMPv6
  traffic only got the common IPv6 fields, no type/echo breakdown. Added as
  its own branch, but flagged as needing verification against your own
  traffic: pfSense/Netgate has been observed emitting different protocol-text
  values across versions (`ICMPv6` vs `ipv6-icmp`), and a known upstream
  decoding issue in some releases can render this field as the name of a
  preceding IPv6 extension header instead of the real protocol.

## Deployment

1. Deploy the rsyslog config on the pfSense box (or wherever filterlog is
   forwarded from) so it emits CEF to the local AMA collector port.
2. Confirm `CommonSecurityLog` is receiving rows with
   `DeviceVendor == "NETGATE"` and `DeviceEventClassID == "filterlog"`.
3. Save `vimNetworkSessionPfsenseCustom` as a function first, then
   `ASimNetworkSessionPfsenseCustom` (it calls the former).
4. Register both in your workspace's `Im_NetworkSessionCustom` /
   `ASim_NetworkSessionCustom` "Custom" slots.
