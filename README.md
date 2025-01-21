# 🛸 Bug Hunter - Full Scanner 🛸

**Bug Hunter** is a comprehensive and advanced tool tailored for bug bounty hunters, offering streamlined subdomain discovery, directory scanning, parameter extraction, and vulnerability detection. With its intuitive GUI, Bug Hunter integrates various tools and techniques to provide a seamless and efficient bug-hunting experience.

<img src="https://raw.githubusercontent.com/capture0x/Bug-Hunter/refs/heads/main/screenshots/6.png" width="100%"></img>

## ⚙️ Features 

### ✅ Subdomain Discovery
- **Automated Scanning**: Leverages tools like `subfinder`, `assetfinder`, and APIs such as `Certspotter` and `crt.sh` to discover subdomains.
- **Validation**: Filters and validates subdomains using `httpx` to identify live targets.

### ✅ Directory Scanning
- **FFUF Integration**: Performs directory brute-forcing on identified subdomains using `ffuf`.
- **Customizable Wordlists**: Supports customizable wordlists for tailored scans.
- **Smart Filtering**: Focuses on HTTP status codes `200` and `403` for meaningful results.
- **Formatted Output**: Saves results in a structured format for easy interpretation.

### ✅ Parameter Extraction
- **ParamSpider Integration**: Extracts URL parameters for vulnerability analysis.
- **Intelligent Filtering**: Retains only meaningful results for further exploration.

### ✅ XSS Detection
- **Automated XSS Scanning**: Identifies common vulnerabilities using integrated tools.
- **Custom Scripts**: Supports custom scripts for advanced scans.

### 📑 Results Management
- **Organized Storage**: Automatically saves all scan results into the `results` directory.
- **Real-Time Feedback**: Displays progress and results dynamically in the GUI.

### 🎊 Graphical User Interface (GUI)
- **User-Friendly Design**: Built with Tkinter for an intuitive and responsive experience.
- **Custom Styling**: Highlights critical information with color-coded outputs.

## 💻 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/capture0x/Bug-Hunter.git
   cd Bug-Hunter
   
2. Install dependencies:
   - **Ensure Python 3.x is installed.**
   - **Install required Python packages**:
     ```bash
     pip install -r requirements.txt
     chmod +x install.sh
     bash install.sh
  - **Install additional tools like** `subfinder`, `assetfinder`, `ffuf`, `httpx`, and `ParamSpider`
#### :warning: Important

**Do not forget to run the `install.sh` script! This step is crucial to set up the environment correctly.**

3. Run the application:
    `python3 bug.py`
## 🕹️ Usage

1. **Launch the application** using the command above.
2. **Enter the target domain** in the input field.
3. **Click "Start Full Scan"** to initiate the scanning process.
4. **Monitor real-time results** in the GUI.
5. **Access saved results** in the `results` directory.

## 🔋 Workflow

### Subdomain Discovery
- **Discover subdomains** with integrated tools.
- **Validate targets** to identify live domains.

### Directory Scanning
- **Perform directory brute-forcing**.
- **Save results** with relevant HTTP status codes.

### Parameter Extraction
- **Extract and analyze** URL parameters.

### XSS Detection
- **Identify potential vulnerabilities** using automated scans.

### Results Management
- **Organize and save** all outputs in the `results` folder.

## 💾 Dependencies

- **Python 3.x**
- **Tools**:
  - `subfinder`
  - `assetfinder`
  - `httpx`
  - `ffuf`
  - `ParamSpider`
- **APIs**:
  - `Certspotter`
  - `crt.sh`
- **Libraries**:
  - `PIL` (for image handling)
  - `Tkinter` (for GUI)
  - `subprocess`
  - `threading`
  - `re`
## 📷 Screenshots

<img src="https://raw.githubusercontent.com/capture0x/Bug-Hunter/refs/heads/main/screenshots/1.png" width="32%"></img>
<img src="https://raw.githubusercontent.com/capture0x/Bug-Hunter/refs/heads/main/screenshots/2.png" width="32%"></img>
<img src="https://raw.githubusercontent.com/capture0x/Bug-Hunter/refs/heads/main/screenshots/3.png" width="32%"></img>
<img src="https://raw.githubusercontent.com/capture0x/Bug-Hunter/refs/heads/main/screenshots/4.png" width="32%"></img>
<img src="https://raw.githubusercontent.com/capture0x/Bug-Hunter/refs/heads/main/screenshots/5.png" width="32%"></img>
<img src="https://raw.githubusercontent.com/capture0x/Bug-Hunter/refs/heads/main/screenshots/7.png" width="32%"></img>

## 🤖 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests to enhance the functionality and features of Bug Hunter.

## ⚡ License

This project is licensed under the **GNU General Public License v3.0**. 

You can view the full license details [here](https://www.gnu.org/licenses/gpl-3.0.en.html).

## 🪄 Author

Developed with passion by **Tmrswrr**.

