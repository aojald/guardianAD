
# GuardianAD: Active Directory Password Security Auditor Tool

A powerful forensic tool designed to analyze password security in Active Directory environments. GuardianAD leverages Hashcat results and NTDS.dit extracts to identify weak credentials, detect password reuse patterns, and uncover potential attack vectors.

## Key Features
- **Hashcat Integration**: Analyzes `hashcat` output containing cracked NTLM hashes and username (`--show --username`)
- **NTDS.dit Analysis**: Examines user extracts from NTDS.dit (compatible with Impacket's `secretsdump.py`)
- **Security Analytics**:
  - Identifies password reuse across accounts
  - Detects similar passwords (threshold: 70%+ character overlap)
  - Evaluates passwords with weak and re-used passwords in enabled accounts
  - Filters out computer accounts and history for streamlined analysis
- **Multi-Format Reporting**: Supports ASCII, HTML, and Excel (XLSX) outputs
- **Historical Analysis**: Compares password history to detect trends and patterns

## Prerequisites
### Required Tools
- Python 3.9+
- [Impacket](https://github.com/fortra/impacket) (specifically `secretsdump.py` for NTDS.dit extraction)
- Hashcat

### Python Dependencies
```bash
pip install prettytable openpyxl
```

## Data Preparation Steps
1. **Extract NTDS.dit** using Impacket:
   ```bash
   secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL -just-dc-ntlm -user-status -history -outputfile ntds_extract
   ```
2. **Crack Hashes** with Hashcat

## Usage Guide
### Basic Analysis
```bash
python guardianAD.py hashcat_output ntds_extract.ntds
```

### Advanced Options
```bash
usage: guardianAD.py  [-h] [--filter-history] [--filter-computers] [--only-enabled]
                    [--output {ascii,html,excel}] [--output-file OUTPUT_FILE]
                    hashcat_file ntds_file

Analyze password hashes from Hashcat output and NTDS dump

positional arguments:
  hashcat_file         Path to Hashcat output file
  ntds_file            Path to NTDS dump file

options:
   -h, --help           show this help message and exit
   --filter-history     Exclude password history entries
   --filter-computers   Filter out computer accounts
   --only-enabled       Analyze only enabled accounts
   --output {ascii,html,excel}
                        Specify output format (default: ascii)
   --output-file OUTPUT_FILE
                        Name of the output file (without extension)
```

## Report Metrics Overview
| **Category**            | **Metrics**                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| **Account Analysis**    | Total accounts analyzed, Enabled user count, Computer account count       |
| **Password Security**   | Percentage of cracked passwords, Reused credentials detected             |
| **Similarity Analysis** | Password pairs with >70% character overlap                                |
| **Hash Reuse Detection**| Instances of NTLM hash reuse                                              |

## Important Security Notice
- Treat output files as sensitive security artifacts; handle them with care.
- Always obtain proper authorization before conducting audits.
- Designed for defensive security assessments only.

GuardianAD is your comprehensive tool for auditing and enhancing password security in Active Directory environments.
