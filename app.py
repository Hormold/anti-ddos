import time
import os
import subprocess
import select
import re
import time
from dotenv import load_dotenv
from cf import Cloudflare

load_dotenv()

if not os.environ.get('CLOUDFLARE_API_KEY'):    
    print('CLOUDFLARE_API_KEY is not set')
    exit(1)

cloudflare = Cloudflare(os.environ.get('CLOUDFLARE_API_KEY'))

routes_to_exclude = [
    'socket.io/'
]

access_log = '/var/log/nginx/access.log'
# Access log format (ipv4)
regex = r"(?P<ipaddress>.+?) - - \[(?P<dateandtime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] \"(\w+) (?P<url>.+?(?=\ http\/1.1\")) http\/1.1\" \d{3} \d+ \"(?P<http_host>.+?(?=\"))\" (?P<http_user_agent>.+\s?(?=\ ))"
lineformat = re.compile(regex, re.IGNORECASE)

def parse_log_line(line):
    match = lineformat.match(line)
    if match:
        return match.groupdict()
    else:
        return None

f = subprocess.Popen(['tail','-F',access_log],\
        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)
# Pass top_urls to subproccess


# Collect top 10 URLs in the last 5 minutes, print it and then drop cache
top_urls = {}
last_call = time.time()

def find_ddos_attack():
    # Determine if there is a ddos attack. Check if anomaly big count of requests to one endpoint (x10 times more than average)
    # If there is a ddos attack, deploy a firewall rule to block all traffic to this endpoint
    global top_urls, rps, last_call

    # Calculate rps
    

    
    top_20_urls = sorted(top_urls.items(), key=lambda x: x[1], reverse=True)[:20]

    # Calculate average
    total = 0
    for url in top_20_urls:
        total += url[1]
    average = total / len(top_20_urls)
    rps = total / (time.time() - last_call)
    print('RPS', rps)
    print('Average', average)

    # Check if there is a ddos attack
    for url in top_20_urls:
        if url[1] > average * 10:
            print('DDOS ATTACK DETECTED', url)

            # Deploy firewall rule

def print_top_urls():
    global top_urls
    # Sort by value, print top 10 (key, value) pairs
    sorted_urls = sorted(top_urls.items(), key=lambda x: x[1], reverse=True)
    print(sorted_urls[:10])
    print('---------------------')
    find_ddos_attack()
    top_urls = {}

lines_scanned = 0

while True:
    if p.poll(1):
        line = str(f.stdout.readline().decode("utf-8"))
        data = parse_log_line(line)
        if data:
            hostname = data['http_host']
            url = data['url'].split("?")[0]
            if any(route in url for route in routes_to_exclude):
                # print('Excluded', url)
                continue
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


        if(lines_scanned % 200 == 0):
            print_top_urls()