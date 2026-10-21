# Netgate pfSense — ASIM parsers (NetworkSession + Authentication)

Normalizes Netgate pfSense logs to the Microsoft Sentinel ASIM **NetworkSession** (firewall
`filterlog`) and **Authentication** (SSH, WebGUI, OpenVPN) schemas, both **v1.0.0**.

There are two ingestion paths. Both are kept while devices migrate:

| Path | Table | Status |
|---|---|---|
| **Raw Syslog** (dedicated rsyslog port + static `[pfsense]` marker) | `Syslog` | **Target.** New parsers: `*PfsenseSyslogCustom`, `*AuthenticationPfsenseCustom` |
| **CEF** (rsyslog reshapes filterlog into CEF) | `CommonSecurityLog` | **Legacy.** Fixed parser kept until every device is migrated |

## Architecture (target)

```
pfSense (RFC 5424, unique hostname)
   │  UDP, remote log server = <collector>:<PFSENSE_PORT>
   ▼
[load balancer, optional]
   ▼
rsyslog collector ── input(port=<PFSENSE_PORT>, ruleset=pfsense_raw)
   │                  template: original PRI/facility/severity/hostname/tag
   │                            + static marker "[pfsense]" before the message
   ▼
Azure Monitor Agent (127.0.0.1:28330) ── DCR (Microsoft-Syslog stream)
   ▼
Syslog table ── ProcessName = filterlog / sshd / openvpn / php-fpm ...
   │            SyslogMessage = "[pfsense] <original message>"
   ├─► vimNetworkSessionPfsenseSyslogCustom / ASimNetworkSessionPfsenseSyslogCustom
   └─► vimAuthenticationPfsenseCustom       / ASimAuthenticationPfsenseCustom
```

## Why raw Syslog instead of CEF

- **The collector-side CEF reshaping drops data silently.** The `field($msg,44,N)` transform
  already lost the ICMP extras and `unreachableport` once without anyone noticing. A KQL parser
  fix also applies to data already ingested; an rsyslog fix only applies to new data.
- **Most CEF fields are re-parsed at query time anyway.** Non-standard keys (`trackerid`,
  `ipversion`, `tcpflags`, `icmptype`, ...) land in `AdditionalExtensions` and have to be
  regex-extracted.
- **The raw CSV is much smaller than the CEF line**, which repeats about 50 `key=` labels.
- **The same path carries Auth/VPN logs.** The filterlog-only CEF path never did.
- **Microsoft ships no pfSense ASIM parser.** The only official content is a bare
  `CommonSecurityLog` filter.

**Why a dedicated port plus a marker:** the source is identified without IP lists or hostname
naming conventions, and without rewriting the facility. Other sources share every facility, and
the facility rewrite was rejected so original severity and facility semantics stay intact. Any
device that sends to the dedicated port is pfSense, and the parsers filter on
`SyslogMessage startswith "[pfsense]"` plus `ProcessName`.

> **Load balancers that SNAT** hide the device source IP from the collector. In that case the
> RFC 5424 hostname is the **only** device identity. A device still on the BSD (RFC 3164)
> format behind such an LB shows up with the LB address as its hostname and cannot be
> attributed. Moving every device to RFC 5424 is therefore priority #1.

## Files

| File | Purpose |
|---|---|
| `PFsense_Rsyslog_Conf_Raw_Syslog.conf` | **Target** rsyslog config: dedicated UDP port → static `[pfsense]` marker → AMA. Includes a commented test-mode rule for dual-feeding a device. |
| `vimNetworkSessionPfsenseSyslogCustom.kql` / `.json` | Filtering NetworkSession parser over `Syslog` (filterlog CSV parsed at query time). Contains an offline `datatable` test block with documentation IPs. |
| `ASimNetworkSessionPfsenseSyslogCustom.kql` / `.json` | Parameter-less wrapper (`disabled` only). |
| `vimAuthenticationPfsenseCustom.kql` / `.json` | Filtering Authentication parser over `Syslog`: SSH, WebGUI and OpenVPN logons, logoffs and failures. |
| `ASimAuthenticationPfsenseCustom.kql` / `.json` | Parameter-less wrapper (`disabled` only). |
| `vimNetworkSessionPfsenseCustom.kql` / `.json` | **Legacy** CEF NetworkSession parser over `CommonSecurityLog` (fixed, see below). |
| `ASimNetworkSessionPfsenseCustom.kql` / `.json` | **Legacy** parameter-less wrapper. |
| `PFsense_Rsyslog_Conf_CEF_Sentinel_Schema.conf` | **Legacy** rsyslog CEF reshaping config (current production). |
| `PFsense_Rsyslog_Conf_CEF_Sentinel_Schema_OLD.conf` | Superseded CEF config, kept for rollback. |

Each `.json` is an ARM `savedSearches` template that contains the exact `.kql` text. Edit the
`.kql`, then regenerate the `.json` so the two never drift. The repo-level `tools/` folder
has the helpers:

| Tool | Use |
|---|---|
| `tools/build_arm.py` | Rebuilds a parser `.json` from its `.kql` (alias, display name, `functionParameters`, description). |
| `tools/make_offline_test.py` | Turns a parser's commented `// datatable(...)` block into a runnable test query, swapping the source table and the final call. |
| `tools/minify_kql.py` | Minifies a query, leaving string literals untouched. Needed for tools with a query-length cap (the Azure MCP log query tool allows 10,000 characters). |

Regenerate-and-test loop after editing `vimNetworkSessionPfsenseSyslogCustom.kql`:

```bash
python tools/make_offline_test.py Pfsense/vimNetworkSessionPfsenseSyslogCustom.kql Syslog NetworkSessionPfsense \
  "union (NetworkSessionPfsense() | project t=strcat('row', EventUid), m=strcat(NetworkDirection,'/',DvcAction,'/',NetworkProtocol)), \
         (NetworkSessionPfsense(dvcaction=dynamic(['Deny'])) | summarize c=count() | extend t='deny=3'), \
         (NetworkSessionPfsense(ipaddr_has_any_prefix=dynamic(['198.51.'])) | summarize c=count() | extend t='ip=3'), \
         (NetworkSessionPfsense(dstportnumber=53) | summarize c=count() | extend t='port53=1'), \
         (NetworkSessionPfsense(hostname_has_any=dynamic(['x'])) | summarize c=count() | extend t='host=0')" > /tmp/ns_test.kql
python tools/minify_kql.py /tmp/ns_test.kql > /tmp/ns_test.min.kql      # run in Log Analytics
python tools/build_arm.py Pfsense/vimNetworkSessionPfsenseSyslogCustom.kql Pfsense/vimNetworkSessionPfsenseSyslogCustom.json \
  vimNetworkSessionPfsenseSyslogCustom "Netgate pfSense NetworkSession Parser (Custom, raw Syslog, parameterized)" \
  "<functionParameters as in the existing .json>" "<description as in the existing .json>"
```

Keep live-data test queries (which hold environment hostnames or IPs) out of the repo.

## Device checklist (every pfSense)

1. **Log Message Format = syslog (RFC 5424)** (Status › System Logs › Settings). It carries
   the hostname and RFC 3339 timestamps; BSD, the default, carries neither. The option should
   need CE 2.5+ / Plus 21.02+ (*verify on your oldest device*), and a currently supported
   release is recommended anyway.
2. **Unique, meaningful hostname** per device. It becomes `DvcHostname`/`DvcFQDN`. NTP must be
   configured.
3. **Remote logging:** server `<collector-or-LB>:<PFSENSE_PORT>`. Remote Syslog Contents:
   **Firewall Events, General Authentication Events, VPN Events**. Set Source Address to a
   fixed interface.
4. **Pass traffic is only logged per rule.** Tick "Log packets that are handled by this rule"
   on key outbound and published-service rules. Leave the default block/bogon/private logging
   on and "default pass" logging off, because it is very noisy.
5. **Lower IPsec (charon) log verbosity** (VPN › IPsec › Advanced Settings › IPsec Logging
   Controls). At default or debug levels it was by far the noisiest non-firewall source.
6. **Close SSH on WAN** wherever it isn't required. Internet brute force against
   `root`/`admin` was observed on a few devices.
7. **Transport:** the built-in syslogd sends **UDP only**. TCP or TLS needs the `syslog-ng`
   package, or a VPN/stunnel.
8. **MAC addresses and client hostnames are never in filterlog**, which is L3/L4 only. They
   can only come from DHCP server logs, joined on IP within the lease time: ISC
   `DHCPACK on <ip> to <mac> (<host>)`, or Kea lease logs. ISC DHCP is end-of-life upstream
   and pfSense is moving to Kea. This is deferred, because few devices serve DHCP.
   filterlog doesn't carry rule descriptions either, only the tracker ID. An optional
   watchlist (device, tracker) → description, exported from `config.xml`, could enrich
   `NetworkRuleName` later.

## Collector and DCR prerequisites

- **Collector config:** deploy `PFsense_Rsyslog_Conf_Raw_Syslog.conf`, for example as
  `/etc/rsyslog.d/05-pfsense-raw.conf`. It doesn't load imudp, because the AMA forwarder
  install script already does. Validate with `rsyslogd -N1`. On RHEL with SELinux, run
  `semanage port -a -t syslogd_port_t -p udp <PFSENSE_PORT>`.
- **Network:** the firewall and LB must forward `<PFSENSE_PORT>`/UDP to the collector(s).
- **DCR:** the Syslog DCR must collect the facilities pfSense uses (local0 filterlog,
  auth/authpriv, daemon, user) at `info` or above.
- **Timestamps:** the forwarded message uses AMA's own RFC 3164 format, which has no
  timezone. `Syslog.EventTime` therefore holds the device's local time labelled as UTC (a
  +120 min skew was observed on CEST devices). The parsers use `TimeGenerated`.

## Cost fixes found during analysis

- **The CEF lines are also ingested into `Syslog`.** The CEF template header
  (`<pri>timestamp host CEF:...`) has no tag, so the Syslog DCR also accepts it on `local0`,
  with `ProcessName` set to a timestamp fragment. That made a full duplicate of the pfSense CEF
  volume in `Syslog` (millions of rows per hour). Until CEF is retired, drop those rows with a
  transformation on the **Syslog** stream of the DCR:

  ```kusto
  source
  | where not(SyslogMessage contains "CEF:0|NETGATE|pfsense")
  ```

- **IPsec (charon) verbosity** (checklist item 5).

## Parser notes

### `vimNetworkSessionPfsenseSyslogCustom`
- **Indexes:** filterlog CSV indexes follow Netgate's *Raw Filter Log Format*. IPv4 protocol
  data starts at index 20 and IPv6 at index 17 (0-based, after the marker).
- **`NetworkDirection`** comes from address scopes: RFC 1918, CGNAT, link-local, loopback,
  multicast and broadcast count as local, as do IPv6 ULA, link-local and multicast.
  Local→public is Outbound, public→local is Inbound, local↔local is Local. Only when both ends
  are public (typically scans of the firewall's own WAN address) does pf's `in`/`out` decide.
  pf's per-interface direction is **not** network direction ("in" on a LAN interface is
  outbound traffic). It is kept in `AdditionalFields.PfDirection` and drives
  `DvcInbound/OutboundInterface`.
- **Rules:** `NetworkRuleName` = pf tracker ID, which stays stable across rule reordering.
  `NetworkRuleNumber` = rule ordinal.
- **Result details:** `EventResultDetails` = `NA` (the field is an enumeration). pf's reason
  goes to `EventOriginalResultDetails`.
- **ICMP:** `NetworkIcmpType` holds the RFC 792/4443 name and `NetworkIcmpCode` the type
  number, following the schema doc's example. The ICMP sub-code and the raw type-specific
  fields are in `AdditionalFields`.
- **TCP flags:** pf flags `S A F R P U E W` map to the `TcpFlags*` booleans.
- **Repeats:** `message repeated N times: [...]` lines (syslogd de-duplication) are unwrapped
  and `EventCount` = N.
- **Filter parameters:**
  - `dvcaction` is matched **after** normalization (`Allow`/`Deny`).
  - IP filters use `has_any_ipv4_prefix()` and set `ASimMatchingIpAddr`.
  - `hostname_has_any` returns no rows, because filterlog has no Src/Dst hostnames.

### `vimAuthenticationPfsenseCustom`
Only message shapes observed in production are mapped, and anything else is dropped:

| Process | Message | Mapped to |
|---|---|---|
| sshd | `Accepted <method> for <u> from <ip> port <p>` | Logon / Success (`password`→Username & Password, `publickey`→PKI, `keyboard-interactive/pam`→PAM) |
| sshd | `Failed <method> for [invalid user ]<u> from <ip> port <p>` | Logon / Failure (`No such user` / `Incorrect password` / `Incorrect key`) |
| sshd | `Disconnected from user <u> <ip> port <p>` | Logoff |
| php-fpm | `/<page>.php: Successful login for user '<u>' from: <ip> (<auth source>)` | Logon / Success, `TargetAppName` = pfSense WebGUI |
| php-fpm | `/<page>.php: webConfigurator authentication error for user '<u>' from: <ip>` | Logon / Failure |
| openvpn, php-fpm | `[NOTICE [OpenVPN] ]user '<u>' authenticated` | Logon / Success |
| openvpn | `user '<u>' could not authenticate.` | Logon / Failure |
| openvpn | `openvpn server '<srv>' user cert CN '<cn>' address '<ip>[:<p>]' - connected` | Logon / Success (PKI, certificate-only clients) |
| openvpn | `openvpn server '<srv>' user [cert CN ]'<u>' address ... - disconnected` | Logoff |

These are deliberately **not** mapped, because they would double-count the events above:
- sshd `Invalid user ...` (always followed by `Failed ... invalid user`) and
  `error: PAM: Authentication error ...`.
- OpenVPN `- connected` for username/password users. `authenticated` is the more complete
  signal: some devices never log the connected line.
- OpenVPN RADIUS/TLS infrastructure errors.

**Known limitation:** the OpenVPN `user '<u>' authenticated` line has no source IP, so
`SrcIpAddr` is empty for those logons. Correlate with the `- disconnected` line or the
OpenVPN status if needed.

### `vimNetworkSessionPfsenseCustom` (legacy CEF) — fixes in this version
- **Garbage rule and ICMP values:** AMA joins `AdditionalExtensions` with `;`
  (`trackerid=...;ipversion=4;...;options=nop nop TS;...`). The previous `key=([^\s]+)` regex
  captured the whole remainder of the string, so `NetworkRuleName` and `NetworkIcmpType` held
  garbage. Extraction now uses `key=([^;]*)`.
- **`dvcaction` filter:** it compared normalized values (`Deny`) against raw pf values
  (`block`), so `_Im_NetworkSession(dvcaction=['Deny'])` returned nothing from pfSense. It now
  filters after normalization.
- **IP prefix filters:** they used `has_any` and now use `has_any_ipv4_prefix()`.
- **`hostname_has_any`:** it no longer matches the device name or collector `Computer`.
- **`DvcId`:** it is no longer taken from `_ResourceId`, which is the collector VM for
  forwarded logs.
- **`EventResultDetails`:** it is `NA` (an enumeration); the reason goes to
  `EventOriginalResultDetails`.
- **Added:** `NetworkProtocolVersion`, `TcpFlags*`, ICMP name and number, scope-based
  `NetworkDirection`, `DvcIpAddr`, `DvcFQDN`/`DvcDomain`, and schema version 1.0.0.
- **Wrapper:** the parameter-less wrapper now calls `vimNetworkSessionPfsenseCustom` (it
  called a non-existent name) and exposes `disabled`.
- **IPv6 protocol:** IPv6 rows can report an extension header (for example `Options`) instead
  of the transport protocol. This is an upstream filterlog decoding limitation, passed
  through as-is.

> **Redeploying this parser changes live output semantics.** Before you redeploy, review
> analytics rules, hunting queries and workbooks that read pfSense through
> `_Im_NetworkSession` or `vimNetworkSessionPfsenseCustom`:
> - `NetworkDirection` is now scope-based (it used to be pf's per-interface in/out).
> - `NetworkIcmpType` now holds RFC names, and `NetworkIcmpCode` is populated.
> - `EventResultDetails` is `NA`; the reason moved to `EventOriginalResultDetails`.
> - `NetworkRuleName` is now a clean tracker ID.
> - `DvcId`, `CompanyResourceId` and `EventMessage` are no longer emitted.

## Profiling queries (re-run instead of redoing the analysis)

Use short look-backs. Replace `<LB_ADDRESSES>` with your load-balancer/relay addresses, if
any.

```kusto
// Devices on the legacy CEF path, and how much traffic has no device identity
let rule_look_back = 4h;
CommonSecurityLog
| where TimeGenerated >= ago(rule_look_back)
| where DeviceVendor == "NETGATE"
| extend Unattributed = DeviceName in (<LB_ADDRESSES>) or isnotnull(parse_ipv4(DeviceName))
| summarize Rows = count(), Devices = dcount(DeviceName) by Unattributed

// What pfSense already sends to Syslog (per process/facility)
let rule_look_back = 4h;
Syslog
| where TimeGenerated >= ago(rule_look_back)
| where SyslogMessage startswith "[pfsense]"   // raw path; before migration filter by your devices
| summarize Rows = count(), Hosts = dcount(HostName) by Facility, ProcessName
| order by Rows desc

// Message shapes per process (find new variants before touching regexes)
let rule_look_back = 4h;
Syslog
| where TimeGenerated >= ago(rule_look_back)
| where SyslogMessage startswith "[pfsense]" and ProcessName in ("sshd", "openvpn", "php-fpm")
| extend Shape = substring(replace_regex(SyslogMessage, @"[0-9]+", "#"), 0, 90)
| summarize Rows = count(), Sample = take_any(SyslogMessage) by ProcessName, Shape
| order by ProcessName asc, Rows desc

// CEF lines duplicated into Syslog (should be 0 after the DCR transformation)
Syslog
| where TimeGenerated >= ago(1h)
| where SyslogMessage contains "CEF:0|NETGATE|pfsense"
| count
```

## Validation status (2026-10-14)

| Item | Status |
|---|---|
| Authentication parser | Validated on 4h of production data (marker simulated): SSH, WebGUI and OpenVPN logon/logoff/failure on more than 130 devices. No bad IPs, no missing users. Output column types checked. |
| NetworkSession Syslog parser | Validated offline (`datatable` block in the `.kql`: IPv4 TCP/UDP/ICMP, IPv6 TCP, repeated lines), plus every filter parameter (`dvcaction`, IP prefixes with `ASimMatchingIpAddr`, `dstportnumber`, `hostname_has_any`, `eventresult`). **Pending:** live test stream. |
| Legacy CEF parser | Validated on production `CommonSecurityLog`: 0 malformed rule names, 0 missing IPs, direction distribution checked. |
| `ASimSchemaTester` / `ASimDataTester` | Not deployed in the workspace yet. Deploy them from the Azure-Sentinel repo and run them on all four parsers. |

## Next steps and cutover

0. **Do today, independent of the migration:** add the DCR transformation from
   *Cost fixes* to stop the CEF→`Syslog` duplication.
1. **Test device:** use a device already on RFC 5424, and add a **second** remote log server
   `<collector>:<PFSENSE_PORT>`. Remote Syslog Contents is most likely shared by all
   configured servers (*verify on the test device*). If it is, enable the test-mode rule in
   the raw conf to drop the device's duplicated non-filterlog lines on the legacy port.
2. **Check the first rows:** `SyslogMessage` starts with `[pfsense]`, `HostName` is the
   device, `ProcessName` is `filterlog`, and no `CEF:` lines appear. Then run
   `vimNetworkSessionPfsenseSyslogCustom` against the live rows and compare it with the CEF
   parser for the same device and time window (row counts; action, direction and protocol
   distributions).
3. **Cut over, per device:** point the device at `<PFSENSE_PORT>` only and remove it from the
   CEF conf.
4. **Register the parsers** in `Im_NetworkSessionCustom` / `ASim_NetworkSessionCustom` and
   `Im_AuthenticationCustom` / `ASim_AuthenticationCustom`. **No device may feed both paths
   in production**, or the unifying parsers double-count.
   - **The Syslog parsers only see devices that already send to the dedicated port.** The
     selection relies on the `[pfsense]` marker. Until a device is migrated, its auth and VPN
     lines arrive on the legacy port without the marker, so
     `vimAuthenticationPfsenseCustom` returns **no rows** for it. That is expected, not a
     parser fault.
5. **Retire CEF:** once the last device has moved, move the legacy CEF files to
   `Pfsense/CEF/`, unregister the CEF parser and remove the DCR transformation.
