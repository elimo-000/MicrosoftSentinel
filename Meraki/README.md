# Cisco Meraki MX — ASIM Network Session parser (Custom)

Reads Cisco Meraki MX syslog data ingested into the `meraki_CL` custom table
via **Custom Logs via AMA** (rsyslog → text file → AMA → DCR → `meraki_CL`),
and normalizes it to the ASIM Network Session schema (v0.2.7).

## Why a custom parser

None of Microsoft's published Meraki parsers cover this ingestion path:

- **`ASimNetworkSessionCiscoMeraki`** targets `CiscoMerakiNativePoller_CL`
  (the REST API/native-poller connector), filtered to `EventOriginalType ==
  "IDS Alert"` only — never reads `meraki_CL`, never carries flow/firewall data.
- **`ASimNetworkSessionCiscoMerakiSyslog`** targets the generic `Syslog`
  table (AMA Syslog connector), not `meraki_CL` — the plain Syslog connector
  mangles Meraki's key=value payloads at the first `=` sign, which is exactly
  why Custom Logs via AMA is used instead.
- The workspace-deployed **`_Im_NetworkSession_CiscoMerakiV11`/`V12`**
  functions assume legacy MMA/OMS-agent columns (`SourceSystem`, `Computer`,
  `MG`, `ManagementGroupName`) that AMA/DCR ingestion never creates — this
  causes a hard `project-away` error on V12, or silent zero rows on V11.

## What it parses

Three event branches, unioned into one Network Session stream:

1. **IP flow tracking** (`ip_flow_start` / `ip_flow_end`) — raw flow records
   with no explicit allow/deny in the payload. Only `ip_flow_start` infers
   `DvcAction = Allow` (a flow being newly tracked implies the firewall let
   it through); `ip_flow_end` is a session-teardown notification, not an
   allow/deny decision in itself, so it's mapped to `DvcAction = Other`
   instead of inheriting the inferred `Allow`. Both are flagged via
   `AdditionalFields.DvcActionInferred` so they stay distinguishable from
   `FirewallFlow` rows where the device explicitly logged the decision.
2. **Firewall rule matches** (`flows` / `firewall` / `vpn_firewall` /
   `cellular_firewall` / `bridge_anyconnect_client_vpn_firewall`) — handles
   both old (`flows allow src=...`) and new (`firewall src=... pattern:
   allow al`) message shapes, plus the numeric inbound-rule encoding
   (`0`=allow, `1`=deny) across Meraki firmware versions.
3. **AnyConnect VPN connection events**, carried under the generic `events`
   LogType — extracts the MX's own endpoint (`Local[ip.port]`) as
   destination and the remote client (`Peer[ip.port]`) as source.

Deliberately **not** parsed: everything else under the `events` LogType
(wireless assoc/disassoc, DHCP anomalies, VRRP, Air Marshal, etc.) — those
map better to other ASIM schemas (Authentication, DHCPEvent) than Network
Session.

Also guards against a real gotcha: LogType is always read from its fixed
token position in the raw message, never inferred by scanning message text
— a device hostname that happens to contain a LogType keyword (e.g.
`mil-firewall.du.it`) would otherwise misclassify every message from that
device.

## Files

| File | Purpose |
|---|---|
| `vimNetworkSessionCiscoMerakiCustom.kql` / `.json` | Parameterized filtering parser — the one that does the actual parsing and supports ASIM's standard filter parameters (time range, IP/port/hostname/action/result filters). |
| `ASimNetworkSessionCiscoMerakiCustom.kql` / `.json` | Parameter-less wrapper around the above, for tools/queries expecting a zero-argument view and for auto-discovery by `_ASim_NetworkSession()`. |

## Deployment

1. Deploy/save `vimNetworkSessionCiscoMerakiCustom` **first** — the wrapper
   function depends on it already existing.
2. Test by pasting the `.kql` into Log Analytics / Sentinel > Logs (or run
   the ARM template against your workspace) and confirm it returns rows.
3. Save as a function named exactly `vimNetworkSessionCiscoMerakiCustom`.
4. Repeat for `ASimNetworkSessionCiscoMerakiCustom`.
5. Register both names in your workspace-deployed `Im_NetworkSessionCustom`
   / `ASim_NetworkSessionCustom` "Custom" slots so `_Im_NetworkSession()` and
   `_ASim_NetworkSession()` pick up this source automatically.
