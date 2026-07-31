# MicrosoftSentinel

Custom ASIM parsers and ingestion configs for log sources that Microsoft's
built-in Sentinel content doesn't cover correctly, plus research notes used
to fix a built-in parser's bug.

| Folder | What it's for |
|---|---|
| [`Meraki/`](Meraki) | Custom ASIM Network Session parser for Cisco Meraki MX, built for the `meraki_CL` custom table (Custom Logs via AMA), since none of Microsoft's published Meraki parsers read that table or carry flow/firewall data. |
| [`Pfsense/`](Pfsense) | Custom ASIM Network Session parser for Netgate pfSense, plus the rsyslog config that reshapes pfSense's `filterlog` into the CEF fields the parser expects. |
| [`SonicWall/`](SonicWall) | Investigation notes on a bug in Microsoft's built-in SonicWall ASIM parser that silently dropped allowed/forwarded traffic records. |

Each parser ships as a matching pair of files:
- **`.kql`** — the raw query, for pasting into Log Analytics / Sentinel Logs to test before saving as a function.
- **`.json`** — an ARM template (`Microsoft.OperationalInsights/workspaces/savedSearches`) that deploys the same query as a saved function, for repeatable/automated deployment.

Every parser follows the standard ASIM custom-source pattern: a parameterized
**`vim...`** filtering function plus a parameter-less **`ASim...`** wrapper
around it, so the source can be picked up both by content that calls the
vendor parser directly and by the unifying `_ASim_NetworkSession()` /
`_Im_NetworkSession()` functions. See each folder's README for
source-specific deployment steps and the reasoning behind each parser.
