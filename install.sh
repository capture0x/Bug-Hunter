#!/usr/bin/env bash
set -euo pipefail

mkdir -p "$HOME/go/bin"
export PATH="$HOME/go/bin:$PATH"

install_go_tool() {
  local pkg="$1"
  echo "[+] Installing $pkg"
  go install "$pkg@latest"
}

install_go_tool github.com/projectdiscovery/subfinder/v2/cmd/subfinder
install_go_tool github.com/tomnomnom/waybackurls
install_go_tool github.com/projectdiscovery/httpx/cmd/httpx
install_go_tool github.com/projectdiscovery/nuclei/v3/cmd/nuclei
install_go_tool github.com/tomnomnom/qsreplace
install_go_tool github.com/tomnomnom/fff
install_go_tool github.com/Emoe/kxss

python3 -m pip install --upgrade pip
python3 -m pip install pillow

echo "[+] Install additional tools manually if needed: amass, ffuf, findomain, paramspider"
