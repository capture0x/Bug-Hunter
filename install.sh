#!/bin/bash

curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux-i386.zip && unzip findomain-linux-i386.zip && chmod +x findomain && sudo mv findomain /usr/bin/findomain
curl -LO https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip && unzip httpx_1.6.9_linux_amd64.zip && chmod +x httpx
git clone https://github.com/projectdiscovery/nuclei-templates.git && echo "Nuclei templates downloaded successfully."
pipx install git+https://github.com/devanshbatham/ParamSpider.git
