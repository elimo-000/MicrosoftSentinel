# Cisco Umbrella (CCF connector) — ASIM Dns parser (Custom)

Reads DNS activity logs ingested via the **Cisco Umbrella data connector
(Codeless Connector Framework / CCF variant)** into the `CiscoUmbrellaDNS_CL`
table, and normalizes it to the ASIM Dns schema (v1.0.0).

## Why a custom parser

Microsoft ships a built-in `Cisco_Umbrella` function ("CiscoUmbrella Data
Parser"), but it is a plain union view across both the legacy
Azure-Function-connector tables (`Cisco_Umbrella_dns_CL`, etc.) and the
newer CCF tables (`CiscoUmbrellaDNS_CL`, etc.) — it does not normalize to
any ASIM schema and is not picked up by `_ASim_Dns()` / `_Im_Dns()`. No
ASIM-schema parser ships for the CCF connector's DNS table at all, so
analytics rules and workbooks built on `_Im_Dns()`/`_ASim_Dns()` see no
Cisco Umbrella DNS data when the CCF connector is used instead of the
Azure Function one.

## Field mapping

`vimDnsCiscoUmbrellaCCFCustom` builds its output with `extend` + `project-away`
rather than a hard `project`, so every raw Cisco Umbrella field (`Identities`,
`IdentityTypes`, `Action`, `RuleId`, `DestinationCountries`, `OrganizationId`,
`QueryType`, `ResponseCode`, ...) survives in the output alongside its
ASIM-mapped name, instead of being silently dropped. Only pure ingestion
metadata with no analytic value is dropped (`Timestamp` once typed into
`EventStartTime`/`EventEndTime`, `Type`, `TenantId`, `_ResourceId`).

Beyond the original mapping, this adds (confirmed against production sample
data):

| Raw field | ASIM field | Why |
|---|---|---|
| `MostGranularIdentity` | `SrcHostname` (Recommended) | Confirmed to be a real client hostname (e.g. `LTGV21-2014`), not an abstract label. |
| `MostGranularIdentityType` | `SrcDescription` (Optional) | Free text (e.g. `Anyconnect Roaming Client`) — not mapped to `SrcDeviceType`, since Umbrella's identity types don't reliably map to ASIM's fixed enum (`Computer`/`Mobile Device`/`IOT Device`/`Other`) without a vendor-wide lookup table. |
| `Action` | `DvcAction` (normalized: `Allowed`→`Allow`, `Blocked`→`Deny`) + `DvcOriginalAction` (raw) | Umbrella's raw wording never equals ASIM's canonical `Allow`/`Deny` — any content filtering on `DvcAction=="Allow"` previously never matched this source. |
| `RuleId` | `RuleName` (Optional, string) | Kept as string rather than cast with `toint()`, in case a future/non-standard deployment emits a non-numeric rule ID. |
| `OrganizationId` | `DvcScopeId` (Optional) | Umbrella's own org/tenant ID for this deployment — analogous to how `DvcScopeId` maps a cloud subscription/account ID for other cloud-delivered sources. |
| `DestinationCountries` | `DstGeoCountry` (Optional) | Can be a comma-separated list when a response resolves to multiple IPs in different countries — a looser fit than the schema's single-country intent, but still useful. |
| `Identities`, `IdentityTypes` | `AdditionalFields` | Full identity chain, in case it differs from the single most-granular identity captured in `SrcHostname`/`SrcDescription` (e.g. a user behind a network device). |

## Files

| File | Purpose |
|---|---|
| `vimDnsCiscoUmbrellaCCFCustom.kql` / `.json` | Parameterized filtering parser — supports ASIM's standard Dns filter parameters (time range, source IP, domain, response code/IP filters). |
| `ASimDnsCiscoUmbrellaCCFCustom.kql` / `.json` | Thin wrapper around `vimDnsCiscoUmbrellaCCFCustom`, called with no-op filter values, keeping only the `disabled` parameter. For tools/queries expecting a (near-)zero-argument view and for auto-discovery by `_ASim_Dns()`. |

## Deployment

1. Deploy/save `vimDnsCiscoUmbrellaCCFCustom` first.
2. Test by pasting the `.kql` into Log Analytics / Sentinel > Logs (or run
   the ARM template against your workspace) and confirm it returns rows.
3. Save as a function named exactly `vimDnsCiscoUmbrellaCCFCustom`.
4. Repeat for `ASimDnsCiscoUmbrellaCCFCustom`.
5. Register `vimDnsCiscoUmbrellaCCFCustom` in the workspace-deployed
   `Im_DnsCustom` function's "Custom" slot, and `ASimDnsCiscoUmbrellaCCFCustom`
   in `ASim_DnsCustom`, so `_Im_Dns()` and `_ASim_Dns()` pick up this source
   automatically.
