# MicrosoftSentinel

Custom ASIM parsers and ingestion configs for log sources that Microsoft's
built-in Sentinel content doesn't cover correctly, plus research notes used
to fix a built-in parser's bug.

| Folder | What it's for |
|---|---|
| [`Pfsense/`](Pfsense) | Custom ASIM NetworkSession (`filterlog`) and Authentication (SSH / WebGUI / OpenVPN) parsers for Netgate pfSense over raw `Syslog`, with the rsyslog config for a dedicated pfSense port that adds a static `[pfsense]` marker. Also the legacy CEF parser (`CommonSecurityLog`), fixed and kept during migration. The README holds the device checklist, cost findings, validation status and cutover steps. |
| [`SonicWall/`](SonicWall) | Custom ASIM Network Session parser — a patched copy of Microsoft's built-in SonicWall parser, fixing several bugs (including one that silently dropped allowed/forwarded traffic records) found during investigation, plus the investigation notes themselves. |
| [`tools/`](tools) | Helper scripts: rebuild a parser's ARM `.json` from its `.kql` (`build_arm.py`), turn a parser's commented `datatable` block into an offline test query (`make_offline_test.py`), and minify KQL for length-capped query tools (`minify_kql.py`). |
| [`Umbrella/`](Umbrella) | Custom ASIM Dns parser for Cisco Umbrella via the CCF (Codeless Connector Framework) connector, built for the `CiscoUmbrellaDNS_CL` table, since Microsoft's built-in Umbrella parser doesn't normalize to any ASIM schema. |

Each parser ships as a matching pair of files:
- **`.kql`** — the raw query, for pasting into Log Analytics / Sentinel Logs to test before saving as a function.
- **`.json`** — an ARM template (`Microsoft.OperationalInsights/workspaces/savedSearches`) that deploys the same query as a saved function, for repeatable/automated deployment.

Every parser follows the standard ASIM custom-source pattern: a parameterized
**`vim...`** filtering function plus a parameter-less **`ASim...`** wrapper
around it, so the source can be picked up both by content that calls the
vendor parser directly and by the unifying `_ASim_<Schema>()` / `_Im_<Schema>()` functions
(for example `_Im_NetworkSession()`, `_Im_Authentication()`, `_Im_Dns()`). See each folder's README for
source-specific deployment steps and the reasoning behind each parser.
