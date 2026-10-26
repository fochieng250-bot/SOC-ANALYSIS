# SOC Analysis: Suricata Detection and Log Hunting

## Project summary

This case study documents a blue-team exercise using Suricata to monitor an isolated virtual lab. The exercise correlated a network scan alert with sensor logs, examined suspicious web activity that was recorded but not matched by the expected alert, and identified follow-up work for a SOC analyst.

It represents the SOC/blue-team stage of a larger security-learning portfolio. The source notes described earlier stages covering network and web security concepts and log-parser automation, with a consolidated report planned as a later stage.

> **Safety and privacy:** This is a sanitized account of an authorized, host-only training lab. No personal identity, account name, real lab address, screenshot, raw log, credential, exploit payload, target-specific attack command, or vulnerable service version is included. Do not monitor or test systems without explicit authorization.

## Sanitization

- The source author's name, online handle, age, country, mentor information, and repository path have been removed.
- Original lab addresses have been replaced by addresses from RFC 5737 documentation-only ranges. Those substitutions are illustrative, not the original addresses and not routable lab targets.
- Event times, source ports, and flow identifiers are not preserved. Example records below are descriptive summaries, not copied event data.
- Query parameters and attack strings are redacted. Raw packet and HTTP logs are not included because they can expose sensitive data.
- Commands and procedures for executing scans or web attacks have been omitted. This document focuses on detection, investigation, and defensive response.

## Exercise objective

The lab explored four questions:

1. Can a Suricata sensor on a host-only interface alert on network-service discovery activity?
2. Can a Suricata sensor on loopback record web-application requests in HTTP events?
3. What can an analyst learn from event logs when the expected signature alert is absent?
4. How should the findings be documented, triaged, and used to improve monitoring?

The central lesson was that **alerts and logs are complementary**: a missing signature alert does not prove the absence of suspicious activity.

## Lab environment

| Component | Sanitized description |
|---|---|
| Analyst/test host | Isolated virtual lab host, represented as `192.0.2.41` |
| Training target | Intentionally vulnerable VM, represented as `198.51.100.27` |
| Local web application | Training application accessed through `127.0.0.1:8080` |
| Network sensor | Suricata 8.0.7 |
| Monitored interfaces | Host-only interface for VM-to-VM traffic and loopback for local application traffic |
| Rules | Emerging Threats Open rules |
| Logs | Suricata `fast.log` for alerts and `eve.json` for structured events |
| Supporting tools | Nmap 7.99x and a deliberately vulnerable web training application |

The rule-update output in the source notes recorded 69,237 rules loaded and 53,269 enabled. Counts depend on the ruleset and update date; they are historical lab observations, not recommended or guaranteed values.

The host-only network and loopback are distinct monitoring points. A sensor listening on one does not automatically see traffic on the other.

## Exercise observations

### 1. Network scan detection

The host-only sensor generated four alerts matching:

- **Signature:** `ET SCAN Possible Nmap User-Agent Observed`
- **Signature ID/revision:** `1:2024364:5`
- **Priority:** 1
- **Classification:** Web Application Attack
- **Protocol:** TCP
- **Sanitized direction:** `192.0.2.41` to `198.51.100.27`, destination service port 80

The four alerts appeared within the time window of the lab's service-discovery test. Their timing and common signature provided useful correlation evidence. The source notes interpreted them as repeated probes associated with service identification.

**SOC interpretation:** This is a strong detection lead, not by itself proof of malicious intent. An analyst should establish whether the activity was authorized, identify the relevant assets and owner, and check related host and application logs before deciding on escalation or containment.

### 2. Suspicious web request recorded without the expected alert

The loopback sensor did not produce the expected web SQL-injection signature alert during the training-app test. It did record HTTP activity in `eve.json`, including:

- An HTTP event on the loopback interface.
- A request to the training application's SQL-related page.
- A suspicious query parameter, redacted here.
- A related earlier request recorded as the HTTP referer.
- A successful HTTP response status.
- A browser user-agent value.

Request values, user-agent specifics, timestamps, source ports, and flow IDs are intentionally omitted. The source data showed two related requests during the same exercise; that relationship is preserved here without publishing the request strings.

**SOC interpretation:** The event supports investigating a possible detection gap. An HTTP request record alone does not demonstrate successful exploitation, credential theft, or data exfiltration. Confirm impact using application, database, and endpoint evidence.

### 3. HTTP response anomaly

The alert log contained:

- **Signature:** `SURICATA HTTP Response excessive header repetition`
- **Signature ID/revision:** `1:2221036:1`
- **Priority:** 3
- **Classification:** Generic Protocol Command Decode
- **Context:** Response from the local training application

The source notes considered this likely training-environment or application noise. That is a hypothesis to validate, not a reason to suppress the event automatically. Check the application behavior and baseline before making a tuning change.

### 4. DHCP information event

An informational event matched:

- **Signature:** `ET INFO Possible Kali Linux hostname in DHCP Request Packet`
- **Signature ID/revision:** `1:2022973:1`
- **Protocol:** UDP
- **Context:** DHCP request on the host-only lab network

This provided a possible operating-system clue for lab asset inventory. Hostname or DHCP heuristics are not definitive identity evidence, and the event does not by itself indicate an attack.

## Blue-team findings

| ID | Finding | Evidence | Assessment and suggested action |
|---|---|---|---|
| B-01 | Network scan activity detected | Four priority-1 scan-signature alerts from the host-only interface, correlated with the authorized lab test window. | High-priority triage lead in a production environment. Verify authorization and asset ownership; correlate with endpoint and service logs. Escalate or contain only according to validated context and incident procedures. |
| B-02 | Suspicious web activity logged without the expected SQL-injection alert | HTTP events captured related requests to the local training application, while the expected web SQL-injection alert was absent. Request values are redacted. | Detection gap to investigate. Review sensor configuration, rule coverage, application logs, and database telemetry. The available IDS evidence does not establish successful exploitation or exfiltration. |
| B-03 | HTTP response header anomaly | Priority-3 protocol-decode event associated with the training application. | Informational observation. Validate whether the behavior is expected; tune only with supporting evidence and documented rationale. |
| B-04 | Lab host possibly identified by DHCP metadata | Informational DHCP signature suggesting a Kali host on the isolated network. | Asset-inventory clue only. Confirm with authorized inventory rather than treating the signature as conclusive attribution. |

Suricata priority is not a CVSS score. Severity should reflect the environment, authorization, affected assets, evidence of impact, and organizational triage policy. The source notes' original characterization of the web event as confirmed critical exfiltration was not supported by the recorded IDS evidence and is not carried forward.

## Investigation workflow

1. **Validate scope and authorization.** Confirm whether the observed source and target belong to an approved test or operational activity.
2. **Build a timeline.** Correlate the alert and HTTP event timestamps with firewall, endpoint, web-server, and database logs. Use synchronized clocks where possible.
3. **Confirm sensor coverage.** Verify that the sensor observed the correct interfaces and that the relevant protocols and event types are enabled.
4. **Review alerts and events together.** Examine `fast.log` for signature alerts and `eve.json` for structured HTTP and flow context. A missing alert is not proof of no activity.
5. **Determine impact.** Validate suspicious requests against server-side behavior and database or endpoint evidence; do not infer compromise from a request record alone.
6. **Document and escalate.** Record evidence, confidence, affected assets, and unresolved questions. Follow the organization's incident-response process before containment.
7. **Protect the evidence.** Restrict access to raw logs and redact credentials, tokens, personal information, and sensitive URL parameters before sharing.

## Defensive improvement plan

### Review the detection gap

- Confirm the ruleset is current and compatible with the deployed Suricata version.
- Review HTTP protocol parsing, logging configuration, and rule coverage for the observed class of event.
- Reproduce validation only with controlled, benign fixtures in an isolated lab.
- Measure both detection coverage and false-positive impact before deploying a rule change.

### Tune with care

- Investigate informational DHCP and HTTP anomaly events before filtering them.
- Prefer narrow, documented exceptions over broad suppressions.
- Record the reason, owner, validation results, and review date for each tuning change.
- Reassess tuning when the application, ruleset, or network architecture changes.

### Improve SIEM and incident response

- Forward appropriately filtered Suricata events to a SIEM such as Wazuh.
- Correlate network events with asset inventory and application/endpoint telemetry.
- Create an investigation ticket with a clear timeline, evidence references, confidence, and next steps.
- Use approved response procedures for escalation or containment; do not automatically block an address solely because of a lab-like signature.

No custom detection rule or sensor-reload command is published here. Any custom rule should be written and tested by authorized defenders against representative, non-sensitive lab fixtures before production deployment.

## Evidence checklist

The original exercise planned evidence in these categories. No screenshots, raw logs, or request values are published in this repository.

| # | Evidence category | Safe handling |
|---|---|---|
| 1 | Suricata version and ruleset summary | Share version and counts only when useful; redact hostnames and local paths. |
| 2 | Sensor process and interface coverage | Redact usernames, process details, and real network configuration. |
| 3 | Network scan signature alert | Replace source/destination addresses, timestamps, and source ports. |
| 4 | HTTP anomaly alert | Replace loopback flow details and timestamps; preserve signature and priority if relevant. |
| 5 | HTTP event showing alert/log discrepancy | Redact query parameters, referer values, user-agent details, timestamps, and flow identifiers. |
| 6 | Interface and application context | Describe the interface and training-app role without publishing real addresses or identities. |
| 7 | Future tuning validation | Include test method and measured result only after sanitizing all sensitive data. |

## Key learnings

| Concept | Exercise observation | SOC relevance |
|---|---|---|
| IDS versus IPS | The sensor observed and logged traffic; it was not a firewall blocking the activity. | Detection and response are separate functions. Coordinate any blocking action with the responsible controls and incident process. |
| Alerts versus logs | A scan signature alerted; suspicious HTTP activity was present in structured events without the expected signature alert. | Analysts should investigate relevant event data as well as signature alerts. |
| Interface coverage | Host-only and loopback traffic required monitoring at their respective interfaces. | Map sensor placement to the network and host traffic that needs visibility. |
| False positives and false negatives | Informational host metadata and a response anomaly needed context; the web activity illustrated a possible missed alert. | Detection tuning should balance coverage and operational noise using evidence. |
| Blue-team perspective | The exercise compared a test activity with the evidence available to the defender. | Controlled lab work can help analysts understand what their sensors do and do not observe. |

## Portfolio context

The source notes placed this work after several learning stages on network and web security topics and log-parser automation. This stage emphasized blue-team visibility with Suricata, followed by a planned combined report. Offensive lab procedures and unrelated findings are intentionally excluded from this public repository.

## License

The source notes specified CC BY-NC 4.0 for the original portfolio material. This sanitized summary preserves that stated licensing context; consult the license terms before reuse.

---

This document summarizes a controlled training exercise. It is for defensive education and does not authorize testing or monitoring systems outside an explicitly approved scope.
