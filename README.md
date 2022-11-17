# rec-on-go

Rec-on-go is a python baseline recon tool based in some go tools.

## Install

Just run the `installer.sh` bash file.

## Modes:
### Passive: 
In passive mode run the following tools to get subdomains:
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [sublist3r](https://github.com/aboul3la/Sublist3r)
- [amass](https://github.com/OWASP/Amass)

Then merge the subdomain's on a unique set of subdomain's.

Once the list of unique subdomains is obtained, a passive port fetch is executed using [naabu](https://github.com/projectdiscovery/naabu) with the passive option.

With the subdomain:port listing, [httpx](https://github.com/projectdiscovery/httpx) will be executed to obtain the corresponding urls.

With all the urls obtained, [gowitness](https://github.com/sensepost/gowitness) is executed in order to obtain screenshots.


### Active:
In active mode it runs the same tools as in passive mode, but naabu runs with the --top-ports=1000 option to get a wider scope of services.
Also after getting the urls and screenshots, [katana](https://github.com/projectdiscovery/katana) runs to get endpoints, and also runs [nuclei](https://github.com/projectdiscovery/nuclei) to scan for vulnerabilities.


It is configured to send subdomains, subdomains:port, URLS and vulnerabilities through notify. To configure it, it must be configured with one of the available services.
The channels id are:
- Subdomains: `subdomains`
- Subdomains:port: `naabu`
- URL: `urls`
- Vulnerabilities: `scan`


## Usage

`-p` is the project name value used to make the directory output. 

For only one domain passive scan:

`python3 gominator.py -d example.com -p example -s passive`

For list domains passive scan:

`python3 gominator.py -i domains.txt -p example -s passive`

For only one domain active scan:

`python3 gominator.py -d example.com -p example -s active`

For list domains active scan:

`python3 gominator.py -i domains.txt -p example -s active`


### Nuclei connector
It use the nuclei reporting feature to send vulnerabilities to other services like elasticsearch. You must provide a [config file](https://nuclei.projectdiscovery.io/nuclei/get-started/#nuclei-reporting) to set the connection.

`python3 gominator.py -i domains.txt -p example -s active -nc config-connector.yaml`
