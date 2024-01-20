# SMB Share Discovery Tool

## Overview
The SMB Share Discovery Tool is a Python-based application designed to discover, mount, and unmount SMB shares on a network. It utilizes the Zeroconf protocol for service discovery and provides a graphical user interface (GUI) built with Tkinter. This tool allows users to scan for SMB servers, list available shares, and manage mount points with ease.

![FalseMount Demo](https://github.com/SCNickF1227/FalseMount/blob/main/2024-01-20_13-33-13.gif)

## Features
- Discover SMB servers on the local network.
- List available shares on discovered servers.
- Mount and unmount shares with specified drive letters.
- View status of mounted shares.
- Log all activities to a file.

## Requirements
- Python 3
- Zeroconf library
- Tkinter library (usually included in standard Python installation)

## Dependencies
The application requires the following Python libraries:
- Zeroconf: For service discovery using the Zeroconf protocol.
- Tkinter: For the graphical user interface.

Ensure these dependencies are installed and up-to-date in your Python environment to run the application successfully.

## Installation
To install the SMB Share Discovery Tool, clone or download the repository to your local machine and ensure all dependencies are satisfied.

## Usage
1. Launch the program with Python: `python smb_discovery.py`
2. Use the GUI to scan for SMB servers, view shares, and manage mount points.

### Scanning for SMB Servers
- Click on the "Scan for SMB Servers" button to discover available SMB servers on the network.

### Managing Shares
- Select a server to view its available shares.
- Choose a share and a drive letter, then click "Mount Share" to mount it.
- To unmount a share, select it and click "Unmount Share".

## Logging
- The application logs all activities, including server discovery, mounting, and unmounting operations, in `smb_discovery.log`.

## Contributing
Contributions to the SMB Share Discovery Tool are welcome. Please feel free to fork the repository, make your changes, and submit a pull request.

## Disclaimer
This tool is provided as-is, and the developers are not responsible for any misuse or damage caused by this software.
