# Nmap2CSV
![nmap-parser-logo](https://img.shields.io/badge/nmap-parser-blue?style=flat-square&logo=ruby&logoColor=white)

This CLI tool is yet another **Nmap XML file(s)** parser to extract host and service information and generates detailed CSV reports. It supports both individual XML files and directories containing multiple Nmap reports.

This tool is intended to parse large-scale Nmap scans and make the extracted host and service data more digestible and actionable-especially when dealing with numerous targets or comprehensive scans.

---


## Usage

```bash
./nmap2csv.rb --file <file_or_directory> [--output <output_directory>]
```

### Examples

#### Parsing a Single XML File
```bash
./nmap2csv.rb --file /path/to/nmap_scan.xml
```

### CSV Outputs

#### **Services CSV**
```csv
"IP-Address";"Hostname";"Mac";"Mac-Vendor";"OS name";"Port";"Protocol";"Service";"State";"Tunnel";"HTTP-Title";"Info";"CPE";"Vulners"
"45.33.32.156";"scanme.nmap.org";"";"";"Actiontec MI424WR-GEN3I WAP";"22";"tcp";"ssh";"open";"";"";"OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 Ubuntu Linux; protocol 2.0";"cpe:/a:openbsd:openssh:6.6.1p1";"https://vulners.com/cve/CVE-2023-38408"
"45.33.32.156";"scanme.nmap.org";"";"";"Actiontec MI424WR-GEN3I WAP";"80";"tcp";"http";"open";"";"Go ahead and ScanMe!";"Apache httpd 2.4.7 (Ubuntu)";"cpe:/a:apache:http_server:2.4.7";"https://vulners.com/githubexploit/C94CBDE1-4CC5-5C06-9D18-23CAB216705E"
```

#### **Hosts CSV**
```csv
"IP-Address";"Hostname";"Mac";"Mac-Vendor";"OS"
"45.33.32.156";"scanme.nmap.org";"";"";"Actiontec MI424WR-GEN3I WAP"
```
---

## Features

- Extracts **host details** and generates a `hosts.csv` file containing:
  - IP addresses
  - MAC addresses
  - Hostnames
  - Operating System information (OS name, flavor, and service pack).

- Extracts **service details** and generates a `services.csv` file containing:
  - IP addresses, Hostnames, MAC addresses, OS information.
  - Port information (number, protocol type `tcp/udp`, state).
  - Service attributes:
    - Service name (with confidence filtering; only services with a confidence > 5 are included).
    - `tunnel` attribute (e.g., SSL).
    - Script ID `http-title` output (e.g., HTTP content title for that port/service).
    - Product, version, and extra information.
    - `CPE` if present and vulns

- Supports:
  - Single XML file parsing.
  - Directory-level parsing of all `.xml` files.
  - Deduplication to avoid duplicate entries in CSV files.

- Flexible and allows output to a custom directory.

---

## Nmap Settings

Nmap parameters I tend to reuse...
```bash
nmap -sV --script='default or vulners or http-headers or http-server-header or https-redirect or banner or smb-* or *-version' \
  -oX discovery scanme.nmap.org
```

[Checkout my Nmap runner script!](https://gist.github.com/dreizehnutters/c235ffeb2b4b8e915908e335738381de)

---

## Installation

### Prerequisites
- **Ruby** (version 2.6 or higher)
- The `nokogiri` gem: Install it using:
  ```bash
  gem install nokogiri
  ```

### Download the Tool

Clone the repository to your local machine:
```bash
git clone https://github.com/dreizehnutters/nmap2csv.git
cd nmap2csv
```

---


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---
