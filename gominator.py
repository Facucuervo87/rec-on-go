import subprocess
import os
import errno
import glob
import argparse
import tldextract
import sublist3r


print('------------------------------------------------------')
print(' (                                        )           ')
print(' )\ )            )    (             )  ( /(      (    ')
print('(()/(     (     (     )\   (     ( /(  )\()) (   )(   ')
print(" /(_))_   )\    )\  '((_)  )\ )  )(_))(_))/  )\ (()\  ")
print('(_)) __| ((_) _((_))  (_) _(_/( ((_)_ | |_  ((_) ((_) ')
print("  | (_ |/ _ \| '  \() | || ' \))/ _` ||  _|/ _ \| '_| ")
print('   \___|\___/|_|_|_|  |_||_||_| \__,_| \__|\___/|_|   ')
print('------------------------------------------------------')
print('Not another recon tool...')
print('Powered by: h4kux')

parser = argparse.ArgumentParser(description='Recon script for passive recognition')
parser.add_argument('-d', '--domain', help='Target domain')
parser.add_argument('-i', '--input', help="Target's input file")
parser.add_argument('-p', '--project', help='Project name', required=True)
parser.add_argument('-nc', '--nuclei', help='Nuclei connector file .yaml')
parser.add_argument('-s', '--scan', help='Scan mode must be passive or active.', required=True)

args = parser.parse_args()

scan_type = args.scan

nuclei_config = args.nuclei

input = args.input

cwd = os.getcwd()
print("Current working directory: {0}".format(cwd))


folder = '/recon-' + args.project + '/'

path = cwd + folder

subd_path = path + "subdomains/"

katana_path = path + "katana/"

screenshot_path = path + "screenshots/"

try:
    os.mkdir(path)
    os.mkdir(subd_path)
    os.mkdir(screenshot_path)
    

except OSError as e:
    if e.errno != errno.EEXIST:
        raise

domain = args.domain

print(f"Creating output directory: {path}")
print(f"Creating output directory: {subd_path}")

def recon(domain):
    print("------------------------------------------------------")        
    output_sublist3r = str(subd_path + domain + '-sublist3r.txt')
    output_amass = str(subd_path + domain + '-amass-enum.txt')
    output_subfinder = str(subd_path + domain + '-subfinder.txt')
    print("Running Sublist3r Against: ", domain)
    #sublist3r = subprocess.run(["sublist3r", "-d", domain, "-o", output_sublist3r])
    sublist3r_scan = subdomains = sublist3r.main(domain, 40, output_sublist3r, ports= None, silent=False, verbose= False, enable_bruteforce= False, engines=None)
    print("Finish Sublist3r on domain: ", domain)
    print("------------------------------------------------------")
    print("Running Amass Against: ", domain)
    amass = subprocess.run(["amass", "enum", "-d", domain, "-o", output_amass])
    print("Finish Amass on domain: ", domain)
    print("------------------------------------------------------")
    print("Running Subfinder Against: ", domain)
    subfinder = subprocess.run(["subfinder", "--silent", "-d", domain, "-o", output_subfinder])
    print("Finish Subfinder on domain: ", domain)
    print("------------------------------------------------------")

def merger():
    unique_set = set()
    print("Merging results")
    txt_files = glob.glob(subd_path + '*.txt')
    for f in txt_files:
        for line in open(f,'r'):    
            unique_set.add(line)
    unique_file = subd_path + 'unique' + '-' + args.project + '.txt'
    with open(unique_file,'w') as merged_files:
        for line in unique_set:
            merged_files.write(line)
    print("Sending uniques subdomains to discord")
    subd_notify = subprocess.run(f"notify --silent -data {unique_file} -id subdomains", shell=True)
    return unique_file

def naabu_passive(unique_file):
    print("------------------------------------------------------")
    print("Getting ports with naabu in passive mode")
    output_naabu = path + 'recon-passive.txt'
    naabu = subprocess.run(f"naabu --passive -list {unique_file} -o {output_naabu}", shell=True)
    print(f"Saving results to {output_naabu}") 
    print("Sending Naabu results to discord")
    naabu_notify = subprocess.run(f"notify --silent -data {output_naabu} -id naabu", shell=True)

def naabu_active(unique_file):
    print("------------------------------------------------------")
    print("Getting ports with naabu in active mode")
    output_naabu = path + 'recon-active.txt'
    naabu = subprocess.run(f"naabu -list {unique_file} -top-ports 1000 -o {output_naabu}", shell=True)
    print(f"Saving results to {output_naabu}") 
    print("Sending Naabu results to discord")
    naabu_notify = subprocess.run(f"notify --silent -data {output_naabu} -id naabu", shell=True)

def httpx_passive_url():
    print("------------------------------------------------------")
    print("Getting URLs with httpx") 
    output_httpx = path + domain + '_urls.txt'
    naabu_results = path + 'recon-passive.txt'
    httpx_run = subprocess.run(f"httpx -list {naabu_results} -o {output_httpx}", shell=True)
    print("Sending URL's to discord")
    httpx_notify = subprocess.run(f"notify --silent -data {output_httpx} -id urls", shell=True)
    print(f"URL's file saved to {output_httpx}")

def httpx_active_url():
    print("------------------------------------------------------")
    print("Getting URLs with httpx") 
    output_httpx = path + domain + '_urls.txt'
    naabu_results = path + 'recon-active.txt'
    httpx_run = subprocess.run(f"httpx -list {naabu_results} -o {output_httpx}", shell=True)
    print("Sending URL's to discord")
    httpx_notify = subprocess.run(f"notify --silent -data {output_httpx} -id urls", shell=True)
    print(f"URL's file saved to {output_httpx}")

def screenshot():
    print("------------------------------------------------------")
    print("Tacking Screenshots with gowitness")
    output_httpx = path + domain + '_urls.txt'
    with open(output_httpx, 'r') as file:
        for url in file:
            gowitness = subprocess.run(f"gowitness --disable-db single -P {screenshot_path} {url}", shell=True)
    
def katana():  
    print("------------------------------------------------------")
    print("Running katana against URL")
    try:
        os.mkdir(katana_path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    output_httpx = path + domain + '_urls.txt'
    count = 0
    with open(output_httpx,'r') as file:
        for line in file:
            line = line.split()
            url = line[0]
            extract = tldextract.extract(url)
            subd = extract.subdomain + '.' + extract.domain + '.' + extract.suffix
            output_katana = katana_path + subd + '_katana.txt'
            print(f"Running katana against URL: {url}")
            katana_run = subprocess.run(f"katana -u {url} --silent -o {output_katana}", shell=True)   
    print(f"Katana output saved to {output_katana}")

def nucleiscan():
    print("Starting Nuclei scan against URL's")
    output_httpx = path + domain + '_urls.txt'
    output_nuclei = path + 'nuclei_scan'
        
    if nuclei_config == None:
        print("Scanning nuclei default")
        nuclei = subprocess.run(f"nuclei -l {output_httpx} --silent -o {output_nuclei}", shell=True)
        print(f"Sending scan's results against {domain} to discord")
        nuclei1_notify = subprocess.run(f"notify --silent -data {output_nuclei} -id scan", shell=True)
        
    else:
        config_file = cwd + '/' + nuclei_config
        print(f"Scanning and sending results to connector ussing {config_file}")
        nuclei = subprocess.run(f"nuclei -l {output_httpx} -o {output_nuclei} -rc {config_file}", shell=True)
        print(f"Sending scan's results against {domain} to discord")
        nuclei1_notify = subprocess.run(f"notify --silent -data {output_nuclei} -id scan", shell=True)



if args.domain != None:
    if scan_type == 'passive':
        domain = args.domain
        print(f'Running Gominator agains domain:  {domain} in passive mode')
        recon(domain)
        unique_file = merger()
        output_naabu = naabu_passive(unique_file)
        httpx_passive_url()
        screenshot()

    elif scan_type == 'active':
        domain = args.domain
        print(f'Running Gominator agains domain:  {domain} in active mode')
        recon(domain)
        unique_file = merger()
        output_naabu = naabu_active(unique_file)
        httpx_active_url()
        screenshot()
        katana()
        nucleiscan()


else:
    with open(input,"r") as f:
        lines = f.readlines()
        print(f'Reading domains from list: {input}')
        for line in lines:
            if scan_type == 'passive':
                domain = line.strip()
                print(f'Running Gominator agains domain:  {domain} in passive mode')
                recon(domain)
                unique_file = merger()
                output_naabu = naabu_passive(unique_file)
                httpx_passive_url()
                screenshot()

            elif scan_type == 'active':
                domain = line.strip()
                print(f'Running Gominator agains domain:  {domain} in active mode')
                recon(domain)
                unique_file = merger()
                output_naabu = naabu_active(unique_file)
                httpx_active_url()
                screenshot()
                katana()
                nucleiscan()
            else:
                print('No scan type provided. Please add -s passive for passive scan or -s active to run agressive scan.')


print("----------------------------------------------")
print(f"Recon done, results are on: {path}")
