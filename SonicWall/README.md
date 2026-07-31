# SonicWall — built-in ASIM parser bug notes

Not a custom parser — this is an investigation note explaining a bug found
in **Microsoft's built-in** SonicWall ASIM Network Session parser, kept here
as reference for whoever revisits or patches that parser next.

## The bug

The built-in parser's `gcat in (3, 5, 6, 10)` filter (restricting to
Security Services, Firewall Settings, Network, and Firewall categories)
excludes `gcat` **2 (Log)**. But category 2 is where SonicWall puts its
per-connection "Web site hit" record (`DeviceEventClassID` 97) — the
standard allowed/forwarded traffic event, carrying `fw_action`, src/dst,
ports, rule name, and bytes. Excluding category 2 meant this parser was
silently dropping legitimate allow/forward traffic records.

## `info per categorie log.docx`

Contains:
- The full SonicOS Gen7 `gcat` (syslog group category) table (1–19), used to
  confirm category 2 does carry real traffic records and isn't purely
  administrative logging.
- A walkthrough of the specific `DeviceEventClassID` values referenced in
  the parser's exclusion list, with a call on each: confirmed-correct
  exclusions (rule add/modify/delete — audit events, not traffic),
  the confirmed bug (ID 97, "Web site hit"), and a couple of edge cases
  worth reconsidering (ID 14 "Website Blocked", IDs 646/647 connection-limit
  drops).
- Two `DeviceEventClassID` values (734, 735, 1382) that could **not** be
  confirmed against public SonicOS 7.0.1 documentation — flagged explicitly
  as unconfirmed rather than guessed, since they fall outside the ID ranges
  covered by the available reference material.

Applies to Gen7 platforms (SonicOS 7.0–7.3.x share the same message-ID
space); re-verify before assuming it holds for Gen6 or earlier.
