import nmap
import json
import xmltodict
from xml.etree import ElementTree as ET


# Fonction de scan nmap : on va scanner les hôtes successivement en regardant ports, OS, versions.


def nmap_scanner(ipaddress):
    resultat = {}
    resulthosts = {}
    resultathosts = []
    # print(scan.scan(hosts=ipaddress, arguments='-O -sV', ports='22'))
    state = 'scan en cours...'
    try:
        scan = nmap.PortScanner()
        a = scan.scan(hosts=ipaddress, arguments='-sV -O -sC')
        hosts = scan.all_hosts()
        print(hosts, '\n')
        scan.get_nmap_last_output()
        counter = 0
        print("Nombre d'hôtes trouvés : %s" % len(hosts))
        for host in hosts:
            print(scan[host])
            counter += 1
            hostname = scan[host].hostname()
            reason = scan[host]['status']['reason']
            print(reason)
            state = scan[host].state()
            if reason != "localhost-response":
                mac = scan[host]['addresses']['mac']
                vendor = scan[host]['vendor'][mac]
            else:
                mac = "localhost"
                vendor = ""

            print("\n----------SCANNING HOST n°%s----------" % counter)
            print('\n------------------\nHost information :\n------------------')
            print('Host : %s' % host)

            if hostname != "":
                print('Hostname : %s' % hostname)
            else:
                print('Hostname : (-)')

            if reason != "":
                print('Reason : %s' % reason)
            else:
                print('Reason : (-)')

            if state != "":
                print('State : %s' % state)
            else:
                print('State : (-)')

            # Afficher le scan de l'hôte, du vendor, des protocoles
            # print(scan[host])
            # print(scan[host]["vendor"])
            # print(scan[host].all_protocols())

            print('MAC address : %s\nVendor : %s' % (mac, vendor))

            resulthosts['host'] = host
            resulthosts['state'] = state
            resulthosts['hostname'] = hostname
            resulthosts['reason'] = reason
            resulthosts['mac'] = mac
            resulthosts['vendor(mac)'] = vendor

            resultathosts.append(resulthosts)

            # Mise à jour de la liste à chaque itération
            resultat["host"] = resultathosts

            print(resultat)

            # osmatch = scan[host]['osmatch'].keys('osclass')
            # print(osmatch)
            # ['osclass']['vendor']
            # osfamily = scan[host]['osmatch']['osclass']['osfamily']

            osmatchs = scan[host]['osmatch']
            print(osmatchs)
            # print(len(oss))

            print('\n----------\nOS match :\n----------')

            # osmatch = {osmatch['osmatch']: osmatch for osmatch in scan[host]}

            ct = 0

            for osmatch in osmatchs:
                print(osmatch)
                ct += 1
                osresult = {}
                resultatbis = []
                print("coucou2")
                # print(os)
                # print('allo4')
                print("\nMatch n°%s\n" % ct)
                name = osmatch['name']
                # print(name)
                accuracy = osmatch['accuracy']
                # print(accuracy)
                vendor1 = osmatch['osclass'][0]['vendor']
                # print(vendor1)
                osfamily = osmatch['osclass'][0]['osfamily']
                # print(osfamily)
                osgen = osmatch['osclass'][0]['osgen']
                # print(osgen)
                type = osmatch['osclass'][0]['type']

                print('Accuracy : %s\t OS name : %s\t Vendor : %s\t OS family : %s\t OS gen : %s' %
                      (accuracy, name, vendor1, osfamily, osgen))
                osresult['accuracy'] = accuracy
                osresult['os'] = name
                osresult['vendor'] = vendor1
                osresult['osfamily'] = osfamily
                osresult['osgen'] = osgen

                if int(accuracy) > 85:
                    resultatbis.append(osresult)
                    resultat["os"] = resultatbis
                    print("L'OS est à %s de précision %s" % (accuracy, name))
                    if type == "firewall":
                        print("The scanned device has a %s percentage of being a firewall" % accuracy)

                # print('OSclass : Vendor %s / OSfamily : %s' % (osclass, osfamily))

            for protocol in scan[host].all_protocols():
                print('\n----------------------\nProtocol information :\n----------------------')
                print('Protocol : %s\n' % protocol)

                ports = scan[host][protocol].keys()
                for port in ports:
                    resultatbiss = []
                    resultatbisss = []
                    result = {}
                    state = scan[host]['tcp'][port]['state']
                    reason = scan[host]['tcp'][port]['reason']
                    service = scan[host]['tcp'][port]['name']
                    product = scan[host]['tcp'][port]['product']
                    version = scan[host]['tcp'][port]['version']

                    if state == "closed":
                        print('Port : %s\t \tState : closed' % port)

                    elif state == "filtered":
                        print('Port : %s\t \tState : filtered' % port)

                    else:
                        print('Port : %s\t\tState : %s\t Reason : %s\t Service : %s\t\t\t Product : %s\t\t\t Version : '
                              '%s' % (port, state, reason, service, product, version))
                        result['port'] = port
                        result['state'] = state
                        result['reason'] = reason
                        result['service'] = service
                        result['product'] = product
                        result['version'] = version
                    resultatbiss.append(result)
            resultatbisss += resultatbiss
            resultat["ports"] = resultatbisss

            with open("resultat.json", "w", encoding='utf-8') as file:
                json.dump(resultat, file, ensure_ascii=False, indent=4)
            print(resultat)

            print('\n--------------------\nFirewall discovery :\n--------------------')
            """
            with open('vendorMacsFinal.xml') as vendor:
                try:
                    data = json.load(vendor)
                    data_imp = json.dumps(data)
                    print(data_imp)
                    for vend in data_imp:
                        firewall = []
                        if mac == vend:
                            firewall.append(mac)
                            print(firewall)
                except Exception as e:
                    print(e)

            final_result = json.dumps(resultat)
            """
    except Exception as e:
        print(e)


def resultat_to_json(fichier):
    with open("file2.json", "w", encoding='utf-8') as file:
        json.dump(fichier, file, ensure_ascii=False, indent=4)


print("\n---------Welcome to the nmap scanner tool for Python---------\n")
address = str(input("Please enter a network (or unique address) to scan\n"))

print("\nScan in progress...\n")

nmap_scanner(address)

print("\n-------------------------End of scan-------------------------")
