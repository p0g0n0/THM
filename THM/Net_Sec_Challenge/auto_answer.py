import nmap
'''
1 What is the highest port number being open less than 10,000?
2 There is an open port outside the common 1000 ports; it is above 10,000. What is it?
3 How many TCP ports are open?
4 What is the flag hidden in the HTTP server header?
5 What is the flag hidden in the SSH server header?
6 We have an FTP server listening on a nonstandard port. What is the version of the FTP server?
7 We learned two usernames using social engineering: eddie and quinn. 
    What is the flag hidden in one of these two account files and accessible via FTP?
8 Browsing to http://machine_ip:8080 displays a small challenge that will give you a flag once you solve it. 
    What is the flag?
'''
host = '45.33.32.156'
arguments = '-sS -sC -sV -p 22,25,80,135,139,445,9929,31337 -T4'
highest_less = highest_open = n_open_door = 0
nm = nmap.PortScanner()
nm.scan(hosts=host,arguments=arguments)


s = ''
# print(f"1 What is the highest port number being open less than 10,000?\nAnswer: {s}")
# print(f"2 There is an open port outside the common 1000 ports; it is above 10,000. What is it?\nAnswer: {s}")
# print(f"3 How many TCP ports are open?\nAnswer: {s}")
# print(f"4 What is the flag hidden in the HTTP server header?\nAnswer: {s}")
# print(f"5 What is the flag hidden in the SSH server header?\nAnswer: {s}")
# print(f'''7 We learned two usernames using social engineering: eddie and quinn.
#       \n\tWhat is the flag hidden in one of these two account files and accessible via FTP?\nAnswer: {s}''')
# print(f'''rowsing to http://machine_ip:8080 displays a small challenge that will give you a flag once you solve it. 
#             What is the flag?\nAnswer: {s}''')

'''
--------------------
for port in nm['45.33.32.156']['tcp']:
...     if port < 10000 and nm['45.33.32.156']['tcp'][port]['state']=='open':
...             if port > menor:
...                     menor = port
...     if port > 10000 and nm['45.33.32.156']['tcp'][port]['state']=='open':
...             print(f"maior: {port}")
--------------------
 for port in nm['45.33.32.156']['tcp']:
...     if nm['45.33.32.156']['tcp'][port]['name']=='http':
...             print(nm['45.33.32.156']['tcp'][port]['version'])
--------------------
{'nmap': {'command_line': 'nmap -oX - -sS -sC -sV -p 22,25,80,135,139,445,9929,31337 45.33.32.156', 
'scaninfo': {'tcp': {'method': 'syn', 'services': '22,25,80,135,139,445,9929,31337'}},
'scanstats': {'timestr': 'Mon May 29 22:42:46 2023', 'elapsed': '30.83', 'uphosts': '1', 'downhosts': '0', 'totalhosts': '1'}},
'scan': {'45.33.32.156': {'hostnames': [{'name': 'scanme.nmap.org', 'type': 'PTR'}], 
'addresses': {'ipv4': '45.33.32.156'}, 
'vendor': {}, 'status': {'state': 'up', 'reason': 'echo-reply'}, 
'tcp': {22: 
    {'state':'open', 
    'reason': 'syn-ack', 
    'name': 'ssh', 
    'product': 'OpenSSH', 
    'version': '6.6.1p1 Ubuntu 2ubuntu2.13', 
    'extrainfo': 'Ubuntu Linux; protocol 2.0', 
    'conf': '10', 
    'cpe': 'cpe:/o:linux:linux_kernel', 
    'script': {'ssh-hostkey': '\n  1024 ac00a01a82ffcc5599dc672b34976b75 (DSA)\n  
                                    2048 203d2d44622ab05a9db5b30514c2a6b2 (RSA)\n  
                                    256 9602bb5e57541c4e452f564c4a24b257 (ECDSA)\n  
                                    256 33fa910fe0e17b1f6d05a2b0f1544156 (ED25519)'}}, 
        25: {'state': 'filtered', 'reason': 'no-response', 'name': 'smtp', 'product': '', 'version': '', 'extrainfo': '', 'conf': '3', 'cpe': ''}, 
        80: {'state': 'open', 
        'reason': 'syn-ack', 
        'name': 'http', 
        'product': 'Apache httpd', 
        'version': '2.4.7', 
        'extrainfo': '(Ubuntu)', 
        'conf': '10', 
        'cpe': 'cpe:/a:apache:http_server:2.4.7', 
        'script': {'http-favicon': 'Nmap Project', 
                    'http-title': 'Go ahead and ScanMe!', 
                    'http-server-header': 'Apache/2.4.7 (Ubuntu)'}}, 
        135: {'state': 'filtered', 'reason': 'no-response', 'name': 'msrpc', 'product': '', 'version': '', 'extrainfo': '', 'conf': '3', 'cpe': ''}, 139: {'state': 'filtered', 'reason': 'no-response', 'name': 'netbios-ssn', 'product': '', 'version': '', 'extrainfo': '', 'conf': '3', 'cpe': ''}, 445: {'state': 'filtered', 'reason': 'no-response', 'name': 'microsoft-ds', 'product': '', 'version': '', 'extrainfo': '', 'conf': '3', 'cpe': ''}, 9929: {'state': 'open', 'reason': 'syn-ack', 'name': 'nping-echo', 'product': 'Nping echo', 'version': '', 'extrainfo': '', 'conf': '10', 'cpe': ''}, 31337: {'state': 'open', 'reason': 'syn-ack', 'name': 'tcpwrapped', 'product': '', 'version': '', 'extrainfo': '', 'conf': '8', 'cpe': ''}}}}}
PORT      STATE    SERVICE      VERSION
22/tcp    open     ssh          OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 ac00a01a82ffcc5599dc672b34976b75 (DSA)
|   2048 203d2d44622ab05a9db5b30514c2a6b2 (RSA)
|   256 9602bb5e57541c4e452f564c4a24b257 (ECDSA)
|_  256 33fa910fe0e17b1f6d05a2b0f1544156 (ED25519)
25/tcp    filtered smtp
80/tcp    open     http         Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Go ahead and ScanMe!
|_http-favicon: Nmap Project
|_http-server-header: Apache/2.4.7 (Ubuntu)
135/tcp   filtered msrpc
139/tcp   filtered netbios-ssn
445/tcp   filtered microsoft-ds
9929/tcp  open     nping-echo   Nping echo
31337/tcp open     tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
bla = re.search(r"\w{3}\{\w+\}",result['scan']['45.33.32.156']['tcp'][22]['script']['NULL'])
bla = re.search(r"\w{3}\{\w+\}",result['scan']['45.33.32.156']['tcp'][80]['script']['http-server-header'])
print(bla.group(0))
print(nm['45.33.32.156']['tcp'][80]['version'])
'''