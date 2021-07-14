import nmap

nm = nmap.PortScanner()
print(nm.scan(hosts='192.168.1.-', arguments='-sV -O -p22-443'))

for host in nm.all_hosts():
    print('-----------------------------------')
    print('Hote : %s (%s)' % (host, nm[host].hostname()))
    print('Etat : %s' % nm[host].state())
    for protocol in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % protocol)
    ports = nm[host][protocol].keys()
    for port in ports:
        print('Port : %s\t Etat : %s' % (port, nm[host][protocol][port]['state']))