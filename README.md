# Antivirus Scanner Application

An antivirus scanner application built using Python and Tkinter. This tool enables file and directory scanning, malware detection using hash signatures and YARA rules, and provides features like heuristic analysis, real-time scanning, and file quarantine.

## Features

- **File and Directory Scanning**: Scan individual files or directories for malware.
- **Hash-Based Detection**: Identify malware using known hash signatures.
- **YARA Rules Integration**: Detect malware based on custom YARA rules.
- **Heuristic Analysis**: Identify suspicious patterns in files.
- **Quarantine and Deletion**: Move infected files to a quarantine directory or delete them.
- **Real-Time Scanning**: Monitor directories for file changes in real time.
- **GUI Interface**: User-friendly interface built with Tkinter.
- **Progress Tracking**: Real-time progress bar for scan operations.

## Requirements

- Python 3.6+
- Required Python modules:
  - `tkinter`
  - `hashlib`
  - `yara-python`
  - `watchdog`
  - `concurrent.futures`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/antivirus-scanner.git
   cd antivirus-scanner
