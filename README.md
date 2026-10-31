# Vulnerability Research & Security Reports

A repository dedicated to vulnerability research, disclosure reports, proof-of-concept artifacts, and security advisories.

---

## Vulnerability Reports Catalog

| ID | Target | Component / Applet | Type | Impact | Report Link |
|:---|:---|:---|:---|:---|:---|
| **CAN-2026-2041430** | BusyBox (`v1.38.0` – `v1.39.0.git`) | `archival/rpm.c` (`rpm`, `rpm2cpio`) | CWE-125: Out-of-bounds Read | DoS (Crash), Info Disclosure | [CAN-2026-2041430](./CAN-2026-2041430/) |

---

## Entries

### 1. [CAN-2026-2041430](./CAN-2026-2041430/) — BusyBox Out-of-bounds Read in RPM Parser

* **Candidate / Advisory ID**: `CAN-2026-2041430` (Internal Ref: `BBX-001`)
* **Affected Target**: BusyBox 1.38.0 through Git master (`v1.39.0.git`)
* **Vulnerable File**: `archival/rpm.c` (`rpm_gettags`, `rpm_getstr`, `rpm_getint`)
* **Vulnerability Class**: CWE-125 (Out-of-bounds Read)
* **Summary**:
  When parsing RPM packages, header index offsets and sizes are read from disk without bounds-checking against the mapped data store (`G.mapsize`). Pointers derived from these offsets are subsequently dereferenced in accessor functions (`rpm_getstr`, `rpm_getint`), leading to segmentation faults (Denial of Service) or unintended memory leaks to standard output.
* **Artifacts in Entry Directory**:
  * [Advisory Report (Markdown)](./CAN-2026-2041430/CVE-Busybox-001.md)
  * [Advisory JSON](./CAN-2026-2041430/CVE-Busybox-001.json)
  * [Reproducer & PoCs](./CAN-2026-2041430/busybox/) (`poc_bbx001_gen_rpm.py`, `run_bbx001_repro.sh`, crash inputs)

---

## Repository Structure

Future security reports should follow the directory convention:

```text
my-vuln-report/
├── README.md                          # Master catalog and index
├── CAN-YYYY-XXXXXXX/                  # Report bundle per vulnerability candidate
│   ├── CVE-<Target>-<ID>.md           # Human-readable advisory report
│   ├── CVE-<Target>-<ID>.json         # Machine-readable CVE/vulnerability record
│   ├── README.md                      # Reproduction steps and input manifest
│   └── <target>/                      # Standalone PoC scripts and testcase corpora
```
