# Cloudflare (CCF connector): ASIM WebSession, NetworkSession and Dns parsers (Custom)

Custom ASIM parsers for Cloudflare logs collected with the **Cloudflare data
connector (Codeless Connector Framework / CCF)**. The connector pulls Cloudflare
Logpush batches from storage into the single table `CloudflareV2_CL`.

Microsoft ships no ASIM parser for Cloudflare in any schema, so `_Im_WebSession()`,
`_Im_NetworkSession()` and `_Im_Dns()` see no Cloudflare data without these.

## Files

| Function pair | Schema (version) | Cloudflare dataset | Product |
|---|---|---|---|
| `vimWebSessionCloudflareWAFCustom` / `ASimWebSessionCloudflareWAFCustom` | WebSession (1.0.0) | `http_requests` (inbound WAF / CDN) | WAF |
| `vimWebSessionCloudflareGatewayCustom` / `ASimWebSessionCloudflareGatewayCustom` | WebSession (1.0.0) | `gateway_http` (outbound secure web gateway) | Gateway |
| `vimNetworkSessionCloudflareGatewayCustom` / `ASimNetworkSessionCloudflareGatewayCustom` | NetworkSession (1.0.0) | `gateway_network` + `zero_trust_network_sessions` | Gateway |
| `vimDnsCloudflareGatewayCustom` / `ASimDnsCloudflareGatewayCustom` | Dns (1.0.0) | `gateway_dns` | Gateway |

Each parser ships as a `.kql` file (paste into Logs) and a `.json` ARM template.
The `.json` is generated from the `.kql` with `tools/build_arm.py` and should never be edited by hand.

- `vim…` is the filtering parser, with the schema's standard parameters.
- `ASim…` is a thin, parameterless wrapper around it.

`EventVendor` is `Cloudflare` and `EventProduct` is `WAF` or `Gateway`. Cloudflare
isn't in ASIM's vendor/product list yet. `Dvc` takes the product name, as Learn
recommends for cloud sources with no visible device.

## One table, many datasets

`CloudflareV2_CL` holds **every** Logpush dataset in one ~500-column table. No
column says which dataset a row came from. Each parser selects its rows by the
columns only that dataset fills in:

| Dataset | Fingerprint | Parser |
|---|---|---|
| `http_requests` | `isnotempty(EdgeStartTimestamp)` | WAF WebSession |
| `gateway_http` | `isnotempty(HTTPMethod)` (`HTTPMethod != "UNKNOWN"` for inspected rows) | Gateway WebSession |
| `gateway_network` | `isnotempty(TransportProtocol) and isempty(HTTPMethod)` | Gateway NetworkSession (`Start`) |
| `zero_trust_network_sessions` | `isnotnull(SessionStartTime)` | Gateway NetworkSession (`End`) |
| `gateway_dns` | `isnotempty(QueryName) and isnotempty(ResolverDecision)` | Gateway Dns |
| `firewall_events` | `isnotempty(Kind) and isnotempty(RayID)` | none (see below) |
| `device_posture`, `audit` | `PostureCheckName`, `ActionType` | none |

Each parser keeps only its own dataset's columns with `project-keep`, plus `TimeGenerated`,
`_ItemId`, `Type`, `TenantId` and `_ResourceId`. The raw Cloudflare fields stay in the
output next to the ASIM fields, and the ~450 empty columns from other datasets are dropped.

## How one Gateway connection is logged

A user connection through Cloudflare Gateway produces up to four records. The
parsers map each layer to its own ASIM schema; WebSession is defined as a superset of
NetworkSession for exactly this case.

| Layer | Dataset | Parser / record |
|---|---|---|
| 1. L4 policy decision when the connection opens (allow / block, policy name) | `gateway_network` | NetworkSession, `EventSubType == "Start"` |
| 2. Session summary when it closes (duration, bytes each way, egress IP, close reason) | `zero_trust_network_sessions` | NetworkSession, `EventSubType == "End"` |
| 3. HTTP request (plain HTTP) | `gateway_http` | Gateway WebSession |
| 4. HTTPS request, only when TLS inspection is enabled for it | `gateway_http` | Gateway WebSession |

All of them carry the same Cloudflare `SessionID` in `NetworkSessionId`. In sampled
data, about 92% of `gateway_network` / `gateway_http` session IDs also appear in
`zero_trust_network_sessions`.

The parsers don't join the layers. ASIM parsers must be record-local, a join at
this volume is expensive, and blocked connections have no `End` record.

- **Count connections** with `EventSubType == "Start"`.
- **Sum bytes or duration** over `EventSubType == "End"`.
- **Pivot across layers** on `NetworkSessionId`:

```kusto
let sid = "<SessionID>";
union
    (vimNetworkSessionCloudflareGatewayCustom(starttime=ago(1d)) | where NetworkSessionId == sid),
    (vimWebSessionCloudflareGatewayCustom(starttime=ago(1d)) | where NetworkSessionId == sid)
| project EventStartTime, EventSchema, EventSubType, DvcAction, NetworkRuleName, RuleName,
    DstFQDN, Url, NetworkDuration, SrcBytes, DstBytes, EventResultDetails
| order by EventStartTime asc
```

Cloudflare's `firewall_events` is the **inbound WAF** dataset, not the Gateway
firewall. It has one row per WAF rule match, with the same `RayID` as the request in
`http_requests`. Reading it as well would double-count requests, and the terminating
rule is already in `http_requests` (`SecurityAction`, `SecurityRuleID`,
`SecurityRuleDescription`). It stays in the raw table for per-rule WAF detail.

## Field mapping highlights

### WAF WebSession (`http_requests`)

| ASIM field | Source | Notes |
|---|---|---|
| `EventType` | `HTTPsession` | Cloudflare is an intermediary (reverse proxy). |
| `EventStartTime` / `EventEndTime` | `EdgeStartTimestamp` / `EdgeEndTimestamp` | Real request time; see [Batch delay](#batch-delay-a-point-of-attention-for-detection-rules). |
| `Url` | `ClientRequestScheme://ClientRequestHost` + `ClientRequestURI` | Includes the query string. |
| `EventResultDetails` / `EventResult` | `EdgeResponseStatus` | Status returned to the client: `<400` Success, `>=400` Failure, `0` NA. |
| `DvcAction` / `DvcOriginalAction` | `SecurityAction` | `block`, unsolved challenges, connection close and interstitial pages → `Deny`. No action, `log`, `skip`, `bypass`, `rewrite`, `*Solved`, `*Bypassed` and `linkMazeInjected` → `Allow`. |
| `RuleName` | `SecurityRuleDescription` | `SecurityRuleID` is in `AdditionalFields`. |
| `ThreatRiskLevel` / `ThreatOriginalRiskLevel` | `WAFAttackScore` | Cloudflare: 1 = attack, 99 = clean, 100 = unscored, 0 = not reached. Risk = `100 - score` for 1–99 only. |
| `EventSeverity` | derived | `Deny` → Low. Not denied but attack score 1–20 → **Medium** (an attack that got through). Otherwise Informational. |
| `SrcIpAddr`, `SrcPortNumber`, `SrcGeo*` | `ClientIP`, `ClientSrcPort`, `ClientCountry` / `ClientRegionCode` / `ClientCity` / lat-long | |
| `DstIpAddr` | `OriginIP` | Empty unless `OriginIP` is in the Logpush job. |
| `DstFQDN` / `DstHostname` / `DstDomain` | `ClientRequestHost` (port stripped) | The requested virtual host, so `Dst` is never empty. |
| `DvcIpAddr` | `EdgeServerIP` | Cloudflare edge server that called the origin. |
| `DvcScope` | `ZoneName` | The protected zone. |
| `HttpVersion` | `ClientRequestProtocol` | `HTTP/2` → `2.0`, etc. `NetworkProtocol` is UDP for HTTP/3. |
| `SrcBytes` / `DstBytes` | `ClientRequestBytes` / `EdgeResponseBytes` | |
| `EventOriginalUid` | `RayID` | |

`Cookies` and `RequestHeaders` stay raw and are **not** mapped to `HttpCookie`, because they are sensitive.

### Gateway WebSession (`gateway_http`)

| ASIM field | Source | Notes |
|---|---|---|
| `Url`, `HttpHost`, `HttpRequestMethod`, `HttpVersion` | `URL`, `HTTPHost`, `HTTPMethod`, `HTTPVersion` | |
| `EventResultDetails` / `EventResult` | `HTTPStatusCode` | `0` (no response) → `NA`. |
| `DvcAction` | `Action` | `block` → `Deny`; allow / bypass / isolate / scan variants → `Allow`. |
| `RuleName` | `PolicyName` | |
| `UrlCategory` | `CategoryNames` | |
| `SrcIpAddr` | `SourceInternalIP`, else `SourceIP` | WARP virtual (CGNAT) address, or the LAN address behind a GRE/IPsec on-ramp. The public IP is `AdditionalFields.SourcePublicIP`. `SrcGeoCountry` is the public IP's country. |
| `SrcUsername` (`UPN`), `SrcDvcId` | `Email`, `DeviceID` | Cloudflare's user UUID is not an ASIM `UserIdType`, so it goes in `AdditionalFields.UserID`. |
| `SrcHostname` / `SrcFQDN` / `SrcDomain` | `DeviceName` | `DeviceName` is user-set. When it is a valid host name or FQDN (e.g. `<host>.local`), it is split into these fields. Otherwise (spaces, underscores, an IP), it goes to `SrcDescription`. The raw column is always kept. The same rule applies in the NetworkSession and Dns parsers. |
| `DstIpAddr`, `DstPortNumber`, `DstGeoCountry` | `DestinationIP`, `DestinationPort`, `DestinationIPCountryCode` | |
| `DstFQDN` / `DstHostname` / `DstDomain` | `HTTPHost` (port stripped) | `DstFQDN` only for dotted names. |
| `FileName`, DLP, isolation | `UploadedFileNames`, `BlockedFile*`, `*MatchedDlpProfiles`, `IsIsolated` | First uploaded file name in `FileName`, the rest in `AdditionalFields`. |
| `NetworkSessionId` | `SessionID` | |

**Only inspected rows are returned** (`HTTPMethod != "UNKNOWN"`).

- About 97% of `gateway_http` rows are `Action = bypass`: TLS traffic that Gateway did not decrypt. These rows have no URL, host, method or status.
- They can't fill WebSession's mandatory `Url`, and their L4 data is already in the NetworkSession parser.
- URL-based detections therefore cover only plain HTTP and the HTTPS traffic you inspect.

### Gateway NetworkSession (`gateway_network` + `zero_trust_network_sessions`)

| ASIM field | `Start` (`gateway_network`) | `End` (`zero_trust_network_sessions`) |
|---|---|---|
| `EventStartTime` / `EventEndTime` | `Datetime` | `SessionStartTime` / `SessionEndTime` |
| `DvcAction` | `allow*` → Allow, `block*` → Deny | `Allow` (a proxied session) |
| `NetworkRuleName` | `PolicyName` | — |
| `EventResult` / `EventResultDetails` | Allow → Success, Deny → Failure / `NA` | From `ConnectionCloseReason` (below) |
| `DstIpAddr` / `DstPortNumber` | `DestinationIP` / `DestinationPort` | `OriginIP` / `OriginPort` |
| `SrcBytes` / `DstBytes` / `NetworkBytes` | — | `BytesSent` (client → origin) / `BytesReceived` (origin → client) / sum |
| `NetworkDuration` | — | End − start, in ms |
| `SrcNatIpAddr` / `SrcNatPortNumber` | — | `EgressIP` / `EgressPort` |
| `NetworkDirection` | Private destination → `Local`, else `Outbound` | `Offramp` `INTERNET` → `Outbound`, tunnel / mesh / WARP → `Local` |

`ConnectionCloseReason` maps to the schema's `EventResultDetails` enumeration. The raw value is in `EventOriginalResultDetails`.

| `ConnectionCloseReason` | `EventResultDetails` | `EventResult` |
|---|---|---|
| `CLIENT_CLOSED`, `ORIGIN_CLOSED` | Terminated | Success |
| `CLIENT_IDLE_TIMEOUT` | Timeout | Success |
| `ORIGIN_UNREACHABLE`, `ORIGIN_UNROUTABLE`, `MISMATCHED_IP_VERSIONS` | Routing issue | Failure |
| `PROXY_CONN_REFUSED` | Reset | Failure |
| `TOO_MANY_*`, `EGRESS_PORT_ALLOCATION_ERROR` | Transient error | Failure |
| other errors (`*_ERROR`, `*_TLS_ERROR`) | Unknown | Failure |
| `UNKNOWN` or empty (e.g. UDP) | NA | NA |

Fields shared by both kinds of row:

- `NetworkProtocol`: `tcp` → TCP; `udp` / `quic` → UDP; ICMP / ICMPv6.
- `NetworkApplicationProtocol`: `DetectedProtocol`, upper-cased (TLS, HTTP, SSH, NTP, …).
- `DstFQDN` / `DstHostname` / `DstDomain`: from `SNI`.
- User, device and source IP: as in Gateway WebSession.
- `DvcZone`: the virtual network.
- `hostname_has_any`: matches the device name or the SNI (`DstFQDN` / `DstHostname`) and sets `ASimMatchingHostname`.

### Gateway Dns (`gateway_dns`)

| ASIM field | Source | Notes |
|---|---|---|
| `DnsQuery` | `QueryName` (trailing dot trimmed) | Empty for queries of the root (`.`). |
| `DnsQueryTypeName` / `DnsQueryType` | `QueryTypeName` / `QueryType` | |
| `DnsResponseCode` / `EventResultDetails` | `RCode` (IANA name via `case()`) | Uses `InternalDNSRCode` only when `InternalDNSViewID` is set. Otherwise that field is just `0` and would wrongly mark every query `NOERROR`. |
| `EventResult` | Response code | `0` → Success, other codes → Failure. With no code: blocked → Failure, otherwise `NA`. |
| `DvcAction` / `DvcOriginalAction` | `ResolverDecision` | `blocked*` → Deny; `allowed*` / `override*` → Allow. |
| `RuleName` | `PolicyName` | |
| `UrlCategory` (`DomainCategory`) | `QueryCategoryNames` | |
| `ThreatCategory` | `MatchedIndicatorFeedNames` | |
| `DnsResponseName` | `ResourceRecordsJSON` / `RData` / `ResourceRecords` | The response filters (`response_has_ipv4`, `response_has_any_prefix`) match here and return nothing while it is empty, as the schema specifies. |
| `DnsResponseIpCountry` | First entry of `ResolvedIPCountryCodes` | |
| `SrcIpAddr`, `DstIpAddr` | `SrcIP`, `DstIP` | `DstHostname` = `DstIP`, because the schema requires a hostname whenever `DstIpAddr` is set. |
| `NetworkProtocol` | `Protocol` | `udp` → UDP; DoH (`https`), DoT and TCP → TCP. |
| `DnsSessionId`, `EventOriginalUid` | `QueryID` | |

## Batch delay: a point of attention for detection rules

The path is: Cloudflare Logpush writes batches to storage, and the CCF connector pulls
them. **`TimeGenerated` is therefore the pull time, not the event time.**

Measured on all datasets over 30 minutes:

| Measure | Value |
|---|---|
| `TimeGenerated` − event time | median ≈ 3.5 min, p95 ≈ 6 min. Rare outliers of **over an hour** (`http_requests`, `firewall_events`). |
| `ingestion_time()` − `TimeGenerated` | p95 ≤ 8 s |
| `zero_trust_network_sessions` | Written when the session **ends**, so long-lived sessions arrive with an `EventStartTime` hours older than `TimeGenerated`. |

The parsers put the real event time in `EventStartTime` / `EventEndTime` and leave
`TimeGenerated` untouched. The ASIM `starttime` / `endtime` parameters filter on
`TimeGenerated` by definition.

The parsers keep **`ingestion_time()`** working on their output. It reads a hidden
per-row column, which survives `project-keep`, `extend` and `project-away`.

- It is lost after `summarize`, `join`, `mv-expand` and **`lookup`**.
- An earlier draft of the Dns parser used a `lookup` table for response-code names. It returned a null `ingestion_time()` on every row, so the names are now mapped with `case()`.
- Validation checks `ingestion_time()` is non-null on 100% of rows for all four parsers.

For scheduled analytics rules:

- **Select new rows with `ingestion_time()`**, not `TimeGenerated`, so late batches aren't missed or processed twice:

  ```kusto
  // rule runs every 10 minutes, lookback 1 hour
  vimNetworkSessionCloudflareGatewayCustom(starttime=ago(1h))
  | where ingestion_time() > ago(10m)
  ```

- **Use `EventStartTime` for event-time logic**: correlation windows, "N events within M minutes", and timelines.
- If a rule must window on `TimeGenerated`, make the lookback at least the frequency plus 10 minutes. Outliers can still be missed.
- NRT rules inherit the ~3–6 minute delay.

## Validation

The parsers were validated against live `CloudflareV2_CL` data (15–30 minute windows):

| Check | Result |
|---|---|
| Row count | Each parser returns exactly its fingerprint's row count. The NetworkSession `Start` + `End` counts sum to the combined fingerprint. |
| `ingestion_time()` | Non-null on 100% of rows, for all four parsers. |
| Mandatory fields | Populated on every row, except `DnsQuery` for root (`.`) queries. |
| `DvcAction`, `EventResult`, `EventResultDetails`, `EventSeverity`, `NetworkProtocol`, `HttpVersion` | Only ASIM-allowed values. |
| Filtering parameters | `dvcaction`, `dstportnumber`, `hostname_has_any`, `ipaddr_has_any_prefix`, `eventresult`, `domain_has_any`, `responsecodename`, `response_has_ipv4` and `eventtype` return only matching rows. `ASimMatchingIpAddr` / `ASimMatchingHostname` are set correctly. |
| `ASimSchemaTester` / `ASimDataTester` | **No errors** on any of the four parsers (data tester on a 5,000–10,000 row sample). |

The data tester found real-world problems that the parsers now handle:

- `ThreatRiskLevel` was `long`; it is now cast to `int`.
- `DeviceName` values that are FQDNs, contain spaces or underscores, or are IPs.
- Single-label HTTP hosts in `DstFQDN`.
- An empty `Dst` on WAF rows without `OriginIP`.

Accepted warnings: recommended fields the source doesn't provide.

| Parser | Missing recommended fields | Reason |
|---|---|---|
| All | `DvcHostname`, `DvcDomain`, `DvcIpAddr` | Cloud service with no reporting device. The WAF parser does set `DvcIpAddr` (the edge server). |
| WAF | `SrcHostname`, `SrcDomain` | Internet clients have no host name. |
| Gateway WebSession | `SrcBytes`, `DstBytes` | Not in `gateway_http`; use the NetworkSession `End` record of the same `NetworkSessionId`. |
| Dns | `TransactionIdHex`, `DnsQueryClassName` | Not in `gateway_dns`. |
| Dns | `DnsQuery` empty in about 0.01% of rows | Queries for the root (`.`). |

## Known gaps

- **Gateway HTTP bypass rows** (~97% of `gateway_http`) are not in WebSession; see above.
- **No per-connection single row.** Policy decision and bytes/duration are separate
  NetworkSession records linked by `NetworkSessionId`.
- **Gateway DNS response codes** are mostly unavailable (`EventResultDetails` = `NA`).
  The Logpush job doesn't send `RCode` (see recommendations). Content such as "excessive
  NXDOMAIN" won't fire on this source until it does.
- **Source IP choice.** `SrcIpAddr` is the WARP / internal address, not the public IP,
  so `ipaddr_has_any_prefix` filters don't match the user's public IP. That IP is in
  `AdditionalFields.SourcePublicIP`.
- `has_any_ipv4_prefix` (used by the IP prefix filters) only matches IPv4 addresses.

## Recommendations

1. **Add the missing fields to the Logpush jobs.** The parsers already map them and
   will fill in as soon as they arrive. No parser change is needed.
   - `gateway_dns`: `RCode`, `QueryType`, `ResourceRecordsJSON`. Without these,
     there are no response codes or response IPs.
   - `http_requests`: `OriginIP`, `OriginResponseStatus`, `OriginResponseDurationMs`,
     `EdgeResponseContentType`, `EdgeResponseBodyBytes`, `ClientCity`, `EdgeColoCode`,
     `JA3Hash` / `JA4`, and `BotScore` (requires Bot Management).
2. **Give the table a dataset column, or split it.** Add a DCR transformation that writes
   the dataset name, or route each dataset to its own table. Fingerprinting on sparse
   columns works but is fragile. Learn's parser guidance says the same: when events don't
   identify their source, fix the connector or route them to source-specific tables.
3. **Cost.** `http_requests` is about 70% of the rows. Consider a Basic / Auxiliary
   tier for it, or a DCR filter for cached static-asset hits, if full WAF/CDN detail
   isn't needed for detections.
4. **Sensitive data.** `http_requests` carries full `Cookies` and `RequestHeaders` on
   every row. Consider dropping `Cookies` in the DCR.
5. **TLS inspection coverage.** URL-level WebSession content only sees inspected
   traffic. Review which categories are under "Do Not Inspect".
6. **Other datasets in the table.** `device_posture` and `audit` could later map to
   ASIM AuditEvent, and Access requests (if enabled) to Authentication.
   `firewall_events` stays raw for per-rule WAF detail.

## Deployment

1. Deploy / save each `vim…Custom` function first, then its `ASim…Custom` wrapper.
   - **Portal:** paste the `.kql` into Logs, run it with the last line replaced by a test call (see the DEPLOYMENT notes at the end of each file), then **Save as function** with the exact name and parameter list.
   - **ARM:** deploy the `.json` template.
2. Register the parsers in the workspace-deployed unifying parsers' "Custom" slots:

| Unifying function | Add |
|---|---|
| `Im_WebSessionCustom` | `vimWebSessionCloudflareWAFCustom`, `vimWebSessionCloudflareGatewayCustom` |
| `ASim_WebSessionCustom` | `ASimWebSessionCloudflareWAFCustom`, `ASimWebSessionCloudflareGatewayCustom` |
| `Im_NetworkSessionCustom` | `vimNetworkSessionCloudflareGatewayCustom` |
| `ASim_NetworkSessionCustom` | `ASimNetworkSessionCloudflareGatewayCustom` |
| `Im_DnsCustom` | `vimDnsCloudflareGatewayCustom` |
| `ASim_DnsCustom` | `ASimDnsCloudflareGatewayCustom` |

3. Validate the saved functions with the ASIM testing tools
   (`ASimSchemaTester` / `ASimDataTester`, from https://aka.ms/ASimTestingTools, deployed
   with their ARM templates; both load the ASIM field list from GitHub at run time):

```kusto
vimWebSessionCloudflareWAFCustom | getschema | invoke ASimSchemaTester('WebSession')
vimWebSessionCloudflareWAFCustom(starttime=ago(1h)) | take 5000 | invoke ASimDataTester('WebSession')
```

Earlier Cloudflare functions in the workspace, if any, can be removed once these are
registered and validated. Make sure no analytics rule still calls them.
