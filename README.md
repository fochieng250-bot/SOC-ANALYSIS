# SOC Analysis: Suricata Detection and Log Hunting

## Overview

This case study documents a blue-team exercise using Suricata to observe activity in an isolated, authorized lab. It focuses on correlating IDS alerts with HTTP event logs, identifying a detection gap, and describing practical follow-up for a SOC analyst.

The source notes also covered separate offensive exercises. Their commands, payloads, credential material, vulnerable service details, screenshots, personal details, and real lab identifiers are intentionally not included here.

## Privacy and safety

- No author identity, account name, location, age, personal contact information, or private repository details are included.
- All non-loopback lab addresses below use reserved documentation ranges and are not the original addresses.
- Event times, ports, and flow identifiers are omitted or illustrative.
- No exploit payloads, attack instructions, vulnerable target versions, or raw packet logs are published.
- The exercise was described as a private, host-only virtual lab with a local web application. Do not monitor or test systems without authorization.

## Lab context

| Role | Sanitized description |
|---|---|
| Analyst/test system | Isolated virtual lab host, represented as `192.0.2.41` |
| Test target | Intentionally vulnerable training VM, represented as `198.51.100.27` |
| Local web application | Training application on loopback, represented as `127.0.0.1:8080` |
| Network sensor | Suricata 8.0.7, monitoring a host-only interface and loopback |
| Rules and logs | Emerging Threats Open rules; `fast.log` and `eve.json` |
| Supporting tools | Nmap 7.99x and a deliberately vulnerable training application |

The non-loopback addresses in this table are from the documentation-only ranges defined by RFC 5737; they are substitutions, not routable lab endpoints. `127.0.0.1` is the standard loopback address. The original notes recorded 69,237 rules loaded and 53,269 enabled. These are environment-specific counts, not universal expectations.

## Objective

The exercise examined whether Suricata could:

1. Alert on a network-service discovery activity observed on the host-only interface.
2. Record suspicious web-application requests in HTTP events on loopback.
3. Reveal a gap between signature alerts and information present in logs.
4. Support a concise blue-team findings report and follow-up actions.

## Findings

| ID | Observation | Evidence summary | Assessment and response |
|---|---|---|---|
| B-01 | Network scan activity detected | Four alerts matched `ET SCAN Possible Nmap User-Agent Observed` (signature `1:2024364:5`, priority 1) between the sanitized analyst and target addresses. | High priority in a production environment. Correlate timestamps and asset context; investigate whether the activity was authorized before containment. |
| B-02 | Suspicious web request recorded without a matching SQL-injection alert | No corresponding web SQL-injection signature alert appeared in the observed alert log. The HTTP event log nevertheless recorded a suspicious request and a related prior request to the training application. Request values are deliberately omitted. | Detection gap demonstrated. Review the full HTTP event context and application-side telemetry. The lab evidence does not establish data exfiltration; severity depends on the production context and confirmed impact. |
| B-03 | HTTP response anomaly | Suricata reported `SURICATA HTTP Response excessive header repetition` (signature `1:2221036:1`, priority 3) for the local training application. | Informational in this lab. Validate whether it is expected application behavior before tuning or suppressing it. |
| B-04 | Lab host identified through DHCP metadata | An informational `ET INFO Possible Kali Linux hostname in DHCP Request Packet` event (signature `1:2022973:1`) appeared on the host-only network. | Useful asset context, not proof of malicious activity. Verify the device against the lab inventory. |

Suricata priority is not a CVSS score. The source notes' characterization of the web finding as “critical” or as confirmed exfiltration was not supported by the available IDS evidence, so this public summary does not repeat that conclusion.

## Analysis notes

### Alerts and event logs are complementary

The scan produced signature alerts, while the web request did not produce the expected SQL-injection alert. The HTTP event record still contained useful indicators that supported investigation. Analysts should review relevant `eve.json` events as well as `fast.log`; an absent alert does not prove that no suspicious request occurred.

### Correlate before concluding

- Compare event order and timestamps across sensor, application, and host logs.
- Confirm the monitored interface and asset identity.
- Treat an HTTP anomaly as a signal to investigate, not as proof of an exploit.
- Do not infer credential theft or data exfiltration from a request log alone.

### Monitor the relevant interfaces

The exercise used a host-only interface for VM-to-VM traffic and loopback for local application traffic. Sensor coverage should match the environment: monitoring one interface does not guarantee visibility into traffic on another.

## Recommended defensive follow-up

1. **Validate the alert gap.** Review the installed ruleset and Suricata configuration, then test changes with benign, controlled fixtures in an isolated lab.
2. **Improve visibility.** Retain the HTTP event fields needed for triage, with suitable access controls and retention limits because URLs can contain sensitive data.
3. **Tune carefully.** Investigate informational DHCP and HTTP anomaly events before adding narrow suppressions; document the reason and review tuning periodically.
4. **Correlate with endpoint and application logs.** Forward relevant Suricata events to a SIEM such as Wazuh and associate them with asset inventory and application telemetry.
5. **Use an incident workflow.** Confirm whether the activity is authorized, determine affected assets and impact, preserve evidence, and escalate or contain according to the organization's response plan.
6. **Protect sensitive logs.** Redact credentials, tokens, personal data, and request parameters before sharing samples or publishing reports.

No custom detection rule or sensor-reload command is published here. Any custom rule should be developed and validated by the responsible defenders against representative, non-sensitive lab fixtures before production use.

## Evidence checklist

The source exercise listed these evidence categories. No screenshots or raw logs are included in this repository:

1. Suricata version and ruleset summary.
2. Confirmation that the sensor monitored the intended interfaces.
3. A sanitized scan-alert excerpt.
4. A sanitized HTTP anomaly excerpt.
5. A redacted HTTP event demonstrating the alert/log discrepancy.
6. Interface and asset context for the local application event.
7. Results from any future rule-tuning validation.

## Key takeaways

- An IDS alert is an investigation lead, not a final incident conclusion.
- Event logs can expose activity that signatures did not alert on.
- False positives and false negatives both require context and measured tuning.
- Network, loopback, application, and endpoint telemetry may each provide different parts of the picture.
- Clear evidence, defensible severity, and privacy-aware reporting are core SOC skills.

## Portfolio context

The source notes described this as the fifth of six portfolio stages: earlier stages covered general network and web security concepts and log-parser automation; this stage focused on blue-team monitoring; a consolidated report was planned next. Offensive procedures and unrelated lab details are intentionally excluded.

---

This document is a sanitized summary of an isolated training exercise. It is not an endorsement to scan, probe, or access systems without explicit authorization.
