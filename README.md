# Nmap to Word Report Generator

Generate a penetration testing-style Word report from one or more Nmap results (XML preferred). Multiple inputs (e.g., TCP and UDP scans) are automatically merged into a single report.

## Features

- Parses Nmap XML (`-oX`) with fallback best-effort parsing for text output
- Produces a well-structured `.docx` report using `python-docx`
- Sections include:
  - Title page (assessment, date, assessor)
  - Executive Summary
  - Scope & Methodology (includes Nmap command, version, timings if present)
  - Discovered Hosts Overview (active and all identified hosts)
  - Open Ports & Services (tables per active host)
  - Landscape chart pages with on-page interpretations:
    - Overall Scan Summary (open ports per host)
    - Overall Service Exposure (instances per service across hosts)
    - Sensitive Ports per Host (stacked)
    - Top Ports Across Network (hosts per port)
  - Findings & Recommendations (general guidance)
  - Appendix: Full Nmap Output
- Optional generation of a `pentest.txt` log entry aligned to test methodology, command, results, implications

## Installation

1) Create a virtual environment (recommended)

```
python3 -m venv .venv
source .venv/bin/activate
```

2) Install dependencies

```
pip install -r requirements.txt
```

## Create Nmap Results

Prefer XML output for highest fidelity parsing:

```
nmap -sV -T4 -oX scan.xml 10.0.0.0/24
```

A text output can work in many cases, but the XML is more reliable for parsing.

## Usage

Single file

```
python nmapdocs.py --input scan.xml --output report.docx \
  --assessment "Network Assessment" --assessor "Alice Smith" \
  --scan-command "nmap -sV -T4 -oX scan.xml 10.0.0.0/24" --log-pentest
```

Multiple files (auto-merged, e.g., TCP + UDP)

```
python nmapdocs.py --input windows_tcp.xml windows_udp.xml --output report.docx
```

Arguments:

- `--input` (required): One or more Nmap result files to include (XML preferred; text supported)
- `--output` (required): Path to output `.docx`
- `--assessment`: Assessment title for the report
- `--assessor`: Your name for the title page
- `--scan-command`: Command you used to produce the input (documented in report)

## Notes

- For the best report quality, use Nmap's XML: `-oX scan.xml`.
- The text parser is best-effort and may not capture all fields or edge cases compared to XML.
- The report generator saves the original scan output in the appendix for traceability.

## Examples

```
# 1) Run Nmap, producing XML
nmap -sV -T4 -oX scan.xml 192.168.1.0/24

# 2) Generate the report (single input)
python nmapdocs.py \
  --input scan.xml \
  --output Network_Assessment_Report.docx \
  --assessment "Internal Network PT" \
  --assessor "Red Team" \
  --scan-command "nmap -sV -T4 -oX scan.xml 192.168.1.0/24"

# 3) Generate a merged report (e.g., TCP + UDP)
python nmapdocs.py \
  --input 192.168.1.0_tcp.xml 192.168.1.0_udp.xml \
  --output Network_Assessment_Report.docx
```

## Output

- `Network_Assessment_Report.docx`: A Word document with a security assessment layout.

## Merge Rules (when multiple inputs are provided)

- Hosts are merged by IP address.
- Host status: if any input shows the host as up, the merged host is up.
- Hostname: first non-empty hostname is kept.
- Ports are de-duplicated by `(port, proto)` with preferences:
  - `open` state wins over non-open
  - keep richer `service`, `product`, `version` when available
- Time window: start is the earliest seen; end is the latest seen.
