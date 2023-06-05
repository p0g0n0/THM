import nmap
import re

''''Questions:
    1. What is the highest port number being open less than 10.000? 
    2. There is an open port outside the common 1000 ports; It is above 10.000. What is it? 
    3. How many TCP ports are open? 
    4. What is the flag hidden in the HTTP server header? 
    5. What is the flag hidden in the SSH server header? 
    6. We have an FTP server listening on a nonstanding port. What is the version of the the FTP server? 
    7. We learned two usernames using social engineering: eddie and quinn. What is the
        flag hidden in one of theses two account files and accessible via FTP?
    8. Browsing to HTTP://MACHINE_IP:8080 displays a small challenge that will give you a flag once you solve it.
        What is the flag? challenge_flag'''

nm = nmap.PortScanner()

host = '' # -> Target Machine IP

highest_less = highest_open = n_open_ports = 0
http_flag = ssh_flag = ftp_version = ''
arguments = '-sS -p- -T4 --min-rate=9000'
protocol = 'tcp'
print("THM - NetSec Challenge")
print(''.join('-' for x in range(0,22)))
print("[+] Welcome, first I'll find the open ports")
nm.scan(hosts=host, arguments=arguments)
for port_number in nm[host][protocol]:
    if port_number > highest_open and port_number > 10000 and nm[host][protocol][port_number]['state']=='open':
        highest_open = port_number
        n_open_ports +=1    
    elif port_number > highest_less and port_number < 10000 and nm[host][protocol][port_number]['state']=='open':
        highest_less = port_number
        n_open_ports +=1
print("[+][+] Done.\n[+] Now, I'll look for the answsers to the first 6 questions for you ;)")
ports = ''.join([str(x)+',' for x in nm[host][protocol]]).rstrip(',')
arguments = '-sS -Pn -sV -sC -p '+ports+' -T4 --min-rate=9000'
nm.scan(hosts=host, arguments=arguments)
for port_number in nm[host][protocol]:
    if 'script' in nm[host][protocol][port_number].keys():
        if nm[host][protocol][port_number]['name'] == 'ssh':
            if re.search(r"\w{3}\{\w+\}",nm[host][protocol][port_number]['script']['fingerprint-strings']):
                ssh_flag = re.search(r"\w{3}\{\w+\}",nm[host][protocol][port_number]['script']['fingerprint-strings']).group(0)
                ssh_flag = "Couldn't find it"
        if nm[host][protocol][80]['name'] == 'http':
            if re.search(r"\w{3}\{\w+\}",nm[host][protocol][80]['script']['http-server-header']):
                http_flag = re.search(r"\w{3}\{\w+\}",nm[host][protocol][80]['script']['http-server-header']).group(0)
            else:
                http_flag = "Couldn't find it"
    if nm[host][protocol][port_number]['name'] == 'ftp':
        ftp_version = nm[host][protocol][port_number]['product']+" "+nm[host][protocol][port_number]['version']

print("[+][+] Done.\n[+] Showing the Answers...")
print(''.join('-' for x in range(0,127)))
print(f"1. There is an open port outside the common 1000 ports; It is above 10.000. What is it? \n->Answer: {highest_open}")
print(f'2. There is an open port outside the common 1000 ports; It is above 10.000. What is it? \n->Answer: {highest_less}')
print(f'3. How many TCP ports are open? \n->Answer: {n_open_ports}')
print(f'4. What is the flag hidden in the HTTP server header? \n->Answer: {http_flag}')
print(f'5. What is the flag hidden in the SSH server header? \n->Answer: {ssh_flag}')
print(f'6. We have an FTP server listening on a nonstanding port. What is the version of the the FTP server? \n->Answer: {ftp_version}')
print(''.join('-' for x in range(0,127)))
