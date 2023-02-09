import time
import os
import subprocess
import select
import re
import time
from dotenv import load_dotenv
from cf import Cloudflare
load_dotenv()

SCAN_EVERY = int(os.environ.get('SCAN_EVERY')) if os.environ.get('SCAN_EVERY') else 100
AVARAGE_COEFFICIENT = int(os.environ.get('AVARAGE_COEFFICIENT')) if os.environ.get('AVARAGE_COEFFICIENT') else 10
RPS_MAX = int(os.environ.get('RPS_MAX')) if os.environ.get('RPS_MAX') else 40

if not os.environ.get('CLOUDFLARE_API_KEY'):    
    print('CLOUDFLARE_API_KEY is not set')
    exit(1)

cloudflare = Cloudflare(os.environ.get('CLOUDFLARE_API_KEY'))

lines_scanned = 0
routes_to_exclude = os.environ.get('EXCLUDE_ROUTES').split(",") if os.environ.get('EXCLUDE_ROUTES') else []

# Flow number 1
localCmd = (os.environ.get('LOCAL_LOGS') if os.environ.get('LOCAL_LOGS') else 'tail -f /var/log/nginx/access.log').split(" ")
localLogs = None

# Flow number 2
# We can use this to get logs from remote server (or another file on local server)
remoteCmd = (os.environ.get('REMOTE_LOGS').split(" ") if os.environ.get('REMOTE_LOGS') else None)
remoteLogs = None

# To use this regex, you should edit your nginx config file as shown in README.md
regex = r"(?P<ipaddress>.+?) - - \[(?P<dateandtime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] \"(\w+) (?P<url>.+?(?=\ http\/1.1\")) http\/1.1\" \d{3} \d+ \"(?P<http_host>.+?(?=\"))\" (?P<http_user_agent>.+\s?(?=\ ))"
lineformat = re.compile(regex, re.IGNORECASE)

def average_value(list):
    total = 0
    for item in list:
        total += item
    return total / len(list)

def parse_log_line(line):
    match = lineformat.match(line)
    if match:
        return match.groupdict()
    else:
        return None

localLogs = subprocess.Popen(localCmd,\
        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
if remoteCmd:
    remoteLogs = subprocess.Popen(remoteCmd,\
        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
Poll = select.poll()
Poll.register(localLogs.stdout)
if remoteCmd:
    Poll.register(remoteLogs.stdout)

# Collect top 10 URLs in the last 5 minutes, print it and then drop cache
top_urls = {}
rps_history = []
last_call = time.time()
last_ddos_route = None

def find_ddos_attack():
    # Determine if there is a ddos attack. Check if anomaly big count of requests to one endpoint (x10 times more than average)
    # If there is a ddos attack, deploy a firewall rule to block all traffic to this endpoint
    global top_urls, rps, last_call, last_ddos_route

    # Calculate rps
    top_20_urls = sorted(top_urls.items(), key=lambda x: x[1], reverse=True)[:20]

    # Calculate average
    total = 0
    for url in top_20_urls:
        total += url[1]
    average = total / len(top_20_urls)
    rps = total / (time.time() - last_call)
    rps_history.append(rps)
    print(f'RPS: {rps} | Average RPS: {average_value(rps_history)} | Average: {average} | Total: {total} | Seconds since last stats: {time.time() - last_call}\n---------------------')

    # Check if there is a ddos attack
    for url in top_20_urls:
        if url[1] > average * AVARAGE_COEFFICIENT or (average == url[1] and rps > RPS_MAX):
            # Check if it is the same route as last time
            if last_ddos_route == url[0]:
                continue
            print('DDOS ATTACK DETECTED', url)
            cloudflare.run(url[0], 'challenge')
            last_ddos_route = url[0]

def print_top_urls():
    global top_urls
    # Sort by value, print top 10 (key, value) pairs
    sorted_urls = sorted(top_urls.items(), key=lambda x: x[1], reverse=True)
    # Print top 10 urls
    for url in sorted_urls[:10]:
        print('TOP > ',url[0], url[1])
    print('--------------------- Time: ', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
    find_ddos_attack()
    top_urls = {}


def process_line(line):
    global lines_scanned, top_urls
    data = parse_log_line(line)
    if data:
        hostname = data['http_host']
        url = data['url'].split("?")[0]
        if any(route in url for route in routes_to_exclude):
            return
        ip = data['ipaddress']
        full_url = hostname + url
        print(ip, full_url, lines_scanned)
        if full_url in top_urls:
            top_urls[full_url] += 1
        else:
            top_urls[full_url] = 1
    else:
        print('No match line > ', line)
    lines_scanned += 1


    if(lines_scanned % SCAN_EVERY == 0):
        print_top_urls()



while True:
    if Poll.poll(1):
        if lines_scanned == 0:
            print('Start scanning logs')
        if remoteLogs:
            line = str(remoteLogs.stdout.readline().decode("utf-8"))
            process_line(line)
        if localLogs:
            line2 = str(localLogs.stdout.readline().decode("utf-8")) 
            process_line(line2)