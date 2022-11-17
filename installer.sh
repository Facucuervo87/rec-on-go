#!/bin/bash

printf "##### Dependency installer Working!! #####\n"

sudo apt-get -y update
sudo apt-get -y install git

printf "Installing Python\n"
sudo apt-get install -y python3-pip
sudo apt-get install -y dnspython
pip install tldextract
sudo apt get install python-requests
pip install dnspython
pip install sublist3r

printf "Installing GO\n"
sudo apt install -y golang
export GOROOT=/usr/lib/go
export GOPATH=~/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

echo "export GOROOT=/usr/lib/go" >> ~/.bashrc
echo "export GOPATH=~/go" >> ~/.bashrc
echo "export PATH=$GOPATH/bin:$GOROOT/bin:$PATH" >> ~/.bashrc

source ~/.bashrc

printf "Installing Amass\n"
go install -v github.com/OWASP/Amass/v3/...@master

printf "Installing Subfinder\n"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

printf "Installing httpx\n"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

printf "Installing Notify\n"
go install -v github.com/projectdiscovery/notify/cmd/notify@latest

printf "Installing Nuclei\n"
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

printf "Installing Naabu\n"
sudo apt install -y libpcap-dev
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

printf "Installing Katana\n"
go install github.com/projectdiscovery/katana/cmd/katana@latest

printf "Installing Gowitness\n"

sudo apt install --assume-yes chromium-browser
go install github.com/sensepost/gowitness@latest

sudo su

cp /root/go/bin/* /usr/bin/