# Cisco Umbrella (CCF connector) — ASIM Dns parser (Custom)

Reads DNS activity logs ingested via the **Cisco Umbrella data connector
(Codeless Connector Framework / CCF variant)** into the `CiscoUmbrellaDNS_CL`
table, and normalizes it to the ASIM Dns schema (v0.1.3).

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
