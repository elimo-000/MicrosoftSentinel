# SonicWall Firewall — ASIM Network Session parser (Custom)

A patched copy of Microsoft's official SonicWall Network Session parser
([source](https://github.com/Azure/Azure-Sentinel/blob/master/Parsers/ASimNetworkSession/Parsers/vimNetworkSessionSonicWallFirewall.yaml)),
fixing bugs found while investigating why legitimate allowed traffic wasn't
showing up. Same `CommonSecurityLog` table, same field mappings, same
`AdditionalFields` as the original — everything not listed below is left
exactly as Microsoft ships it. Deliberately named `...Custom` (not
`vimNetworkSessionSonicWallFirewall`) so it coexists in the workspace
without colliding with or being silently overwritten by a future
content-hub update to the official parser.

## Files

| File | Purpose |
|---|---|
| `vimNetworkSessionSonicWallFirewallCustom.kql` / `.json` | Parameterized filtering parser — the patched copy of Microsoft's official parser. |
| `ASimNetworkSessionSonicWallFirewallCustom.kql` / `.json` | Parameter-less wrapper around the above, for pickup by the unifying `_ASim_NetworkSession()` / `_Im_NetworkSession()` functions. |
| `info per categorie log.docx` | Investigation notes behind the fixes below — see "Background" section. |

## Confirmed bugs fixed here

1. **`DeviceEventClassID` 97 ("Web site hit")** — the standard per-connection
   *allowed* traffic record (carries `fw_action="forward"`, src/dst, ports,
   rule name, bytes). The official parser's exclusion list treated ID 97 as
   noise, silently discarding the majority of legitimate forwarded-traffic
   rows. Fixed by removing 97 from the exclusion list.
2. **`gcat` (category) filter** — the official parser's inclusion list
   (`3, 5, 6, 10`) never included `gcat = 2` ("Log"), the category ID 97
   actually lives in. Even with fix #1 alone, these rows would still be
   dropped by this second, independent filter. Fixed by adding `2` to the
   inclusion list.
3. **`DeviceEventClassID` 98 ("Connection Opened") and 537 ("Connection
   Closed")** — a 30-day volume audit found these are by far the largest
   share of this parser's output (~82% of rows), yet neither carried
   `EventSubType` nor a meaningful `DvcAction` (both reported
   `fw_action="NA"`, generically mapped to `Other`/`NA`). Added
   `EventSubType = Start/End` and an inferred `DvcAction = Allow` for these
   two IDs only — a session can only reach "opened"/"closed" state if the
   firewall allowed it in the first place (a denied connection never
   generates these lifecycle records; it gets its own explicit deny/drop
   event instead, and this holds even when the session ends via RST rather
   than a graceful FIN). `DeviceEventClassID` 97 deliberately does **not**
   get this Start/End treatment: it's a mid-session HTTP-layer annotation
   (URL, content-filter category, rule name), not a third session boundary —
   treating it as Start/End would triple-count a single logical session.
4. **`hostname_has_any` filtering was silently broken** — an early
   pre-filter clause dropped every row whenever a hostname filter was
   supplied, regardless of match, because it lacked the "or it matches"
   half of the condition. The parser separately computed a correct
   `ASimMatchingHostname` indicator further down but never actually
   filtered on it. Silent in default use (empty filter list); only
   manifests when a caller actually supplies `hostname_has_any` — same
   "zero rows, no error" failure signature as the Meraki
   `_Im_NetworkSession_CiscoMerakiV11` issue (see [`../Meraki`](../Meraki)).
   Fixed by removing the broken clause and adding the missing
   `| where ASimMatchingHostname != 'No match'` filter.

## Deferred / left as-is (see inline comments in the `.kql` for full reasoning)

- Several repeated `extract()` calls against the same source string
  (AV/anti-spyware/app-control/country fields) violate ASIM's guidance to
  consolidate same-string extracts, but weren't rewritten blind — they feed
  threat-detection fields and need representative samples per message
  variant to verify no regression.
- `EventSchemaVersion` left at `0.2.6` rather than bumped to `0.2.7` without
  verifying actual compliance first (see the `.kql` header for the
  `ASimSchemaTester` command to run before bumping it).
- `DeviceEventClassID` 14 ("Website Blocked") and 646/647 (connection-limit
  drops) are legitimate deny/drop-worthy events still excluded — left alone
  because the exclusion may be intentional (avoiding double-logging /
  rate-limit volume), but worth reconsidering if you're missing these
  specifically.
- `DeviceEventClassID` 734, 735, 1382 could not be confirmed against public
  SonicOS documentation and are left excluded — see "Background" below.

## Background: how the bug was found

`info per categorie log.docx` has the investigation notes behind the fixes
above:
- The full SonicOS Gen7 `gcat` (syslog group category) table (1–19), used to
  confirm category 2 does carry real traffic records and isn't purely
  administrative logging.
- A walkthrough of every `DeviceEventClassID` in the original exclusion
  list, with a call on each: confirmed-correct exclusions (rule
  add/modify/delete — audit events, not traffic), the confirmed bug (ID 97),
  and edge cases worth reconsidering (14, 646, 647 — see above).
- IDs 734, 735, 1382, flagged explicitly as unconfirmed against public
  SonicOS 7.0.1 documentation rather than guessed.

Applies to Gen7 platforms (SonicOS 7.0–7.3.x share the same message-ID
space); re-verify before assuming it holds for Gen6 or earlier.

## Deployment

1. Save `vimNetworkSessionSonicWallFirewallCustom` as a function first, then
   `ASimNetworkSessionSonicWallFirewallCustom` (it calls the former).
2. Register both in your workspace's `Im_NetworkSessionCustom` /
   `ASim_NetworkSessionCustom` "Custom" slots, each under its own
   `Exclude...Custom` disabled-parsers key (don't reuse one from another
   custom parser).
