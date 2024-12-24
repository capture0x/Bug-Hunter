# Bug Hunter - Full Scanner

**Bug Hunter** is a comprehensive and efficient tool designed for bug bounty hunters to streamline subdomain discovery, directory scanning, parameter extraction, and vulnerability identification. This GUI-based scanner integrates multiple tools and techniques to provide a seamless bug hunting experience.

## Installation

### Install dependencies:

- Ensure Python 3.x is installed.
- Install required Python packages:

  ```bash
  pip install -r requirements.txt

    Install tools like subfinder, assetfinder, ffuf, httpx, and others as required.

Run the application:

python bug.py

Usage

    Launch the application using the command above.
    Enter the target domain in the input field.
    Click "Start Full Scan" to initiate the scanning process.
    Results will be displayed in real-time within the GUI and saved in the results directory.

Detailed Workflow
Subdomain Discovery:

    Fetch subdomains using multiple tools like subfinder, assetfinder, and external APIs.
    Validate subdomains by checking their status using httpx.

Directory Scanning:

    Use ffuf to perform directory brute-forcing on identified subdomains.
    Save results with HTTP status codes 200 and 403 in a structured format.

Parameter Extraction:

    Execute ParamSpider to discover parameters in URLs for further analysis.

XSS Scanning:

    Perform automated cross-site scripting (XSS) scans on the target domains.

Results Organization:

    Automatically save and organize all scan results in the results directory for easy access.

Dependencies

    Python 3.x
    Tools:
        subfinder
        assetfinder
        httpx
        ffuf
        ParamSpider
    APIs:
        Certspotter
        crt.sh
    Libraries:
        PIL
        Tkinter
        subprocess
        threading
        re

Screenshots


Contributing

We welcome contributions from the community! Feel free to submit issues, feature requests, or pull requests to help improve Bug Hunter.
License

This project is licensed under the MIT License. See the LICENSE file for more details.

Author

Developed with passion by Tmrswrr.
