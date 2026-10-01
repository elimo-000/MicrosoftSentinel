# MicrosoftSentinel

Custom ASIM parsers and ingestion configs for log sources that Microsoft's
built-in Sentinel content doesn't cover correctly, plus research notes used
to fix a built-in parser's bug.

| Folder | What it's for |
|---|---|
| [`Pfsense/`](Pfsense) | Custom ASIM Network Session parser for Netgate pfSense, plus the rsyslog config that reshapes pfSense's `filterlog` into the CEF fields the parser expects. |
| [`SonicWall/`](SonicWall) | Custom ASIM Network Session parser — a patched copy of Microsoft's built-in SonicWall parser, fixing several bugs (including one that silently dropped allowed/forwarded traffic records) found during investigation, plus the investigation notes themselves. |
| [`Umbrella/`](Umbrella) | Custom ASIM Dns parser for Cisco Umbrella via the CCF (Codeless Connector Framework) connector, built for the `CiscoUmbrellaDNS_CL` table, since Microsoft's built-in Umbrella parser doesn't normalize to any ASIM schema. |

Each parser ships as a matching pair of files:
- **`.kql`** — the raw query, for pasting into Log Analytics / Sentinel Logs to test before saving as a function.
- **`.json`** — an ARM template (`Microsoft.OperationalInsights/workspaces/savedSearches`) that deploys the same query as a saved function, for repeatable/automated deployment.

Every parser follows the standard ASIM custom-source pattern: a parameterized
**`vim...`** filtering function plus a parameter-less **`ASim...`** wrapper
around it, so the source can be picked up both by content that calls the
vendor parser directly and by the unifying `_ASim_NetworkSession()` /
`_Im_NetworkSession()` functions. See each folder's README for
source-specific deployment steps and the reasoning behind each parser.
