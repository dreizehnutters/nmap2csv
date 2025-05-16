![nmap-parser-logo](https://img.shields.io/badge/nmap-parser-blue?style=flat-square&logo=ruby&logoColor=white)

This CLI tool parses **Nmap XML files** to extract host and service information, and generates detailed CSV reports. It supports parsing both single XML files and directories containing multiple XML files.

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
"IP-address";"Hostname";"mac";"mac-vendor";"os_name";"port";"tcp/udp";"protocol";"state";"tunnel";"http-title";"Info"
"192.168.1.1";"example.local";"00:11:22:33:44:55";"Vendor Name";"Linux";"443";"tcp";"http";"open";"ssl";"Example Title";"Apache 2.4.18"
"192.168.1.1";"example.local";"00:11:22:33:44:55";"Vendor Name";"Linux";"22";"tcp";"ssh";"open";;"OpenSSH 7.4p1 protocol 2.0"
```

#### **Hosts CSV**
```csv
"address";"mac";"name";"os_name";"os_flavor";"os_sp"
"192.168.1.1";"00:11:22:33:44:55";"example.local";"Linux";"Debian";"10"
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

- Supports:
  - Single XML file parsing.
  - Directory-level parsing of all `.xml` files.
  - Deduplication to avoid duplicate entries in CSV files.

- Flexible and allows output to a custom directory.

---

## CSV Outputs

### `services.csv`

This file contains information about services detected by Nmap from the parsed files. Below are the columns in the file:

| Column       | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| `IP-address` | The IP address of the host.                                                |
| `Hostname`   | The hostname(s) of the host, comma-separated if multiple exist.            |
| `mac`        | The MAC address of the host (if available).                                |
| `mac-vendor` | The vendor of the MAC address (if available).                              |
| `os_name`    | Operating system name (if detected).                                       |
| `port`       | The port for the given service.                                            |
| `tcp/udp`    | Whether the service is run over TCP or UDP.                                |
| `protocol`   | The service name (e.g., `http`, `ssh`) if identified.                     |
| `state`      | The status of the port (`open`, `closed`, or `filtered`).                  |
| `tunnel`     | The type of tunnel associated with the service (`ssl`, or `null` if none). |
| `http-title` | The output of `<script id="http-title">` if detected.                      |
| `Info`       | Combination of the service's product, version, and additional information. |

### `hosts.csv`

This file contains information about the hosts detected by Nmap from the parsed files. Below are the columns in the file:

| Column     | Description                                                             |
|------------|-------------------------------------------------------------------------|
| `address`  | The IP address of the host.                                             |
| `mac`      | The MAC address of the host (if available).                             |
| `name`     | The hostname(s) of the host, comma-separated if multiple exist.         |
| `os_name`  | The name of the detected operating system.                              |
| `os_flavor`| The flavor of the operating system (e.g., `Debian`, `Windows`).         |
| `os_sp`    | The service pack or generation information of the operating system.     |

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
