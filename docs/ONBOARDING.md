# ULPF Unknown Log Auto-Onboarding Guide
**Zero-Code Log Onboarding with Drain3 Online Template Mining**

---

## 1. Why Template Mining Matters

In real military, intelligence, and large enterprise networks, new appliances and custom software components constantly output unstructured, proprietary log lines. Traditional SIEM solutions require days to weeks of manual regex engineering.

ULPF integrates **Drain3 (LogPAI / IBM Research)**, a streaming online prefix-tree miner, to automate log onboarding completely offline in minutes.

---

## 2. The 5-Step Auto-Onboarding Lifecycle

```
1. UNSEEN LOG INGESTION
   When a log arrives with no matching parser, ULPF preserves the raw event losslessly
   and routes it to the Drain3 Auto-Onboarding Queue.

2. STREAMING TEMPLATE MINING
   Drain3 applies cybersecurity domain maskers (<IP>, <NUM>, <STR>, <TIMESTAMP>)
   and clusters log lines into parameterized templates.

3. CANDIDATE FIELD DISCOVERY & TYPE INFERENCE
   The Field Discovery Engine extracts variable slots and infers types:
   - IPv4 / IPv6 addresses
   - Port numbers (1..65535)
   - Protocols (TCP/UDP/ICMP)
   - Actions / Dispositions (Allow/Deny)
   - Timestamps & Bytes

4. HUMAN-IN-THE-LOOP REVIEW (The Review Studio)
   A SOC Reviewer inspects the discovered template, reviews suggested OCSF mappings,
   adjusts any field names via the web UI, and clicks "Approve & Publish".

5. INSTANT COMPILATION & AUTOMATED REPLAY
   ULPF dynamically compiles a new `Drain3DynamicParser`, registers it as an active
   version in the Parser Registry, and automatically replays all buffered unknown logs!
```

---

## 3. Walkthrough with Real Example

### Raw Unseen Log:
```
[APPLIANCE-FW] 2026-08-27T10:15:40Z DEV=EDGE-FW-09 RULE=BLOCK_SSH SRC=185.220.101.5:49152 DST=10.0.0.5:22 PROTO=TCP ACTION=DENY BYTES=120 REASON="BRUTE_FORCE_BURST"
```

### Discovered Drain3 Template:
```
[APPLIANCE-FW] <TIMESTAMP> DEV=<DEV> RULE=<RULE> SRC=<IP>:<NUM> DST=<IP>:<NUM> PROTO=<PROTO> ACTION=<ACTION> BYTES=<NUM> REASON=<STR>
```

### Inferred Candidate Mappings:
- `<IP>` (Slot 1) $\rightarrow$ `src_endpoint.ip` (Confidence: 95%)
- `<NUM>` (Slot 2) $\rightarrow$ `src_endpoint.port` (Confidence: 92%)
- `<IP>` (Slot 3) $\rightarrow$ `dst_endpoint.ip` (Confidence: 95%)
- `<NUM>` (Slot 4) $\rightarrow$ `dst_endpoint.port` (Confidence: 92%)
- `<PROTO>` $\rightarrow$ `connection_info.protocol_name` (Confidence: 95%)
- `<ACTION>` $\rightarrow$ `disposition` (Confidence: 95%)
- `<NUM>` (Slot 5) $\rightarrow$ `traffic.bytes` (Confidence: 90%)
- `<RULE>` $\rightarrow$ `rule.name` (Confidence: 88%)

### Approval Action:
Clicking **Approve & Publish** immediately registers `appliance-fw-parser:1.0.0`. All future logs of this format are parsed and normalized with zero manual regex coding!
