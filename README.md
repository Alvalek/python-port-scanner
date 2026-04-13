# STower (Signal Tower)

> **High-performance, ethical network reconnaissance engine built with Python.**

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Production-ready-brightgreen)
![Tests](https://img.shields.io/badge/tests-6%20passed-success)

**STower** is a multi-threaded port scanner designed for cybersecurity education and authorized network auditing. It combines speed, accuracy, and detailed service detection to provide a professional-grade reconnaissance tool.

---


##  Description

This tool scans target IP addresses to identify open ports using TCP socket connections. It demonstrates fundamental networking concepts, Python socket programming, and multi-threading techniques.

##  Live Demo

Here is a glimpse of the **Terminal Dashboard** interface:

<img width="1673" height="578" alt="Screenshot_20260412_031852" src="https://github.com/user-attachments/assets/7bcb8b71-c866-453f-bc05-829a72279ad9" />

##  Features

- Multi-Threading: Concurrent scanning using Python's threading module for rapid results.
- Banner Grabbing: Automatically retrieves service banners and identifies software versions (e.g., Apache, Nginx, SSH).
- Data Export: Save scan results in JSON or CSV formats for further analysis.
- Terminal Dashboard: A clean, color-coded CLI interface with real-time status updates.

##  Legal & Ethical Use

  **IMPORTANT**: This tool is meant for authorized security testing.

- Authorization Required: It's not a good idea to scan any network, server, or device without explicit, written permission from the owner.
- Legal Compliance: Unauthorized scanning may violate laws such as the Computer Fraud and Abuse Act (CFAA) in the US, the Computer Misuse Act in the UK, and similar legislation globally.
- Portfolio Context: This project was created for educational purposes to demonstrate proficiency in Python socket programming, multi-threading, and network security concepts.
- Testing Environment: All testing was conducted in controlled, authorized environments (localhost, home labs, and authorized platforms like Hack The Box).




##  Installation

 **Prerequisites**:
  
- Python 3.8 or higher
- pip package manager

**Setup**:<br>
  1. Clone the repository:
```bash
git clone https://github.com/Alvalek/stower.git
cd stower
```
  2. Install dependencies:
```bash
pip install -r requirements.txt
```
(Note: Currently requires only tqdm for the progress bar)


## Usage
**Basic Scan**<br>
Scan the default range (1–1024) on a target:
```bash
python stower.py -t 127.0.0.1
```
**Custom Port Range**<br>
Scan specific ports or a range:
```bash
# Range
python stower.py -t 127.0.0.1 -p 1-10000

# Specific ports
python stower.py -t 127.0.0.1 -p 80,443,8080,3306
```
**Export Results**<br>
Save the output to a file for analysis:
```bash
# JSON format
python stower.py -t 127.0.0.1 -o results.json -f json

# CSV format
python stower.py -t 127.0.0.1 -o results.csv -f csv
```
**Adjust Thread Count**<br>
Increase concurrency for faster scanning (default is 50):
```bash
python stower.py -t 127.0.0.1 -T 100
```
**Full Help Menu**<br>
```bash
python stower.py --help
```

## Project Structure
```bash
stower/
├── stower.py          # Main application logic
├── requirements.txt   # Python dependencies
├── README.md          # Project documentation
├── .gitignore         # Git ignore rules
└── tests/             # Unit tests (coming soon)
```
## License

This project is licensed under the MIT License. See the LICENSE file for details.

##  Smart Host Discovery (`--discover`)
STower uses a **hybrid discovery method**:
```bash
python stower.py -t 192.168.1.1 --discover
```
Uses ICMP ping first, then falls back to TCP handshake on ports 80, 443, and 22. Prevents wasted time on dead hosts.
