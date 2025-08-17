#!/usr/bin/env bash
# Full-setup: Recon/Bug-Hunt Tools & Wordlists/Templates (WSL/Linux/Termux)
set -e

echo "========= Updating package manager ========="
sudo apt update -y && sudo apt upgrade -y

echo "========= Installing essential packages ========="
sudo apt install -y curl wget git unzip python3 python3-pip build-essential

# Go Install/Upgrade (force latest stable for bug-hunt tools)
GO_VERSION="1.22.3"
if ! go version | grep -q "$GO_VERSION"; then
  echo "[+] Installing Go $GO_VERSION ..."
  wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go${GO_VERSION}.linux-amd64.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go${GO_VERSION}.linux-amd64.tar.gz
  export PATH=/usr/local/go/bin:$PATH
fi

export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

mkdir -p "$GOPATH/bin"

echo "========= Installing Go-based tools ========="
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/bp0lr/gauplus@latest
go install github.com/tomnomnom/gf@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

echo "========= Installing Python-based tools ========="
pip3 install --upgrade pip
pip3 install --user sqlmap trufflehog

echo "========= Setting up Corsy ========="
if [ ! -d "$HOME/Corsy" ]; then
  git clone https://github.com/s0md3v/Corsy.git $HOME/Corsy
  pip3 install --user -r $HOME/Corsy/requirements.txt
fi

echo "========= Cloning GF-Patterns ========="
if [ ! -d "$HOME/Gf-Patterns" ]; then
  git clone https://github.com/1ndianl33t/Gf-Patterns $HOME/Gf-Patterns
fi
mkdir -p ~/.gf && cp $HOME/Gf-Patterns/*.json ~/.gf

echo "========= Cloning SecretFinder ========="
if [ ! -d "$HOME/SecretFinder" ]; then
  git clone https://github.com/m4ll0k/SecretFinder.git $HOME/SecretFinder
  pip3 install --user -r $HOME/SecretFinder/requirements.txt
fi

echo "========= Downloading nuclei-templates ========="
if [ ! -d "$HOME/nuclei-templates" ]; then
  git clone https://github.com/projectdiscovery/nuclei-templates.git $HOME/nuclei-templates
else
  cd $HOME/nuclei-templates && git pull && cd -
fi

echo "========= Downloading SecLists (Large, ~2GB) ========="
if [ ! -d "$HOME/SecLists" ]; then
  git clone --depth 1 https://github.com/danielmiessler/SecLists.git $HOME/SecLists
fi

echo "========= Downloading PayloadsAllTheThings ========="
if [ ! -d "$HOME/PayloadsAllTheThings" ]; then
  git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git $HOME/PayloadsAllTheThings
fi

echo "========= Updating nuclei templates ========="
nuclei --update-templates || nuclei -update-templates

echo "🎉 Installation completed successfully!"
echo "✅ All tools, templates, and wordlists are ready to use!"
