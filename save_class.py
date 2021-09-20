import json
import time
import nmap
import xmltodict
import os
import subprocess


class JSONEncode(json.JSONEncoder):
    def serialize_sets(self, obj):
        # Creates a serialized object, used to dump the json object in the convert_xml_json function
        if isinstance(obj, set):
            return list(obj)

        return json.JSONEncoder.default(self, obj)


def conversion_xml_json(xml_file, xml_attribs):
    # Converts an xml file to a json via the json lib, exports the output to a json file
    with open(xml_file, "rb") as fw:
        xml_to_dict = xmltodict.parse(fw, xml_attribs=xml_attribs)
        json_obj = json.dumps(xml_to_dict, default=JSONEncode, indent=4)
        json_serializable = json.loads(json_obj)

        with open("file2.json", "w", encoding='utf-8') as file:
            json.dump(json_serializable, file, ensure_ascii=False, indent=4)
        fw.close()

    return json_serializable


def output_json(output_data, output_file):
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(output_data, file, indent=4)


class NMAPScan:
    def __init__(self, ipaddress, output):
        self.firewalk = ""
        self.scan = nmap.PortScanner()  # Initializing scanning variable scan
        self.scan.scan(hosts=ipaddress, arguments='-sV -O -sC')  # Scanning the ip address or range entered in __main__

        # Defining all the variables used in the NMAPScan class here

        self.hosts = self.scan.all_hosts()
        self.firewall_result = {}
        self.final_score = {}
        self.firewall_protocol_list = []
        self.host_protocol_list = []
        self.scan_hosts = []
        self.is_os_firewall = False
        self.is_mac_vendor = False
        self.is_free_open = False
        self.score = 0
        self.sum_ct = 0
        self.coefficient_1 = 1/2
        self.coefficient_2 = 2
        self.coefficient_3 = 3

        print("Hosts found : %s" % len(self.hosts))
        print("\n--------------SCANNING HOSTS--------------")

        # Scanning each host, os and ports of the designated hosts, then building score and exporting it as a JSON file

        t1 = time.time()
        for host in self.hosts:
            self.scan_host(self.get_host(host), self.get_os(host), self.get_ports(host), self.comparison_vendor(host),
                           self.score_firewall(host, self.host_protocol_list))
        path = "output/" + output
        output_json(self.scan_hosts, path)
        t2 = time.time()

        print("Elapsed time : ", t2-t1)
        print(self.score)

    def get_host(self, host) -> dict:
        # For each scanned host, retrieving basic information on it, outputting data as a dict

        # Variables definition

        hosts_result = {}
        hostname = self.scan[host].hostname()
        reason = self.scan[host]['status']['reason']
        state = self.scan[host].state()

        if reason != "localhost-response":
            if len(self.scan[host]['addresses']) > 1:
                mac = self.scan[host]['addresses']['mac']
                # print(len(self.scan[host]['vendor']))
            else:
                mac = "-"
        else:
            mac = "localhost"
        if len(self.scan[host]['vendor']) != 0:
            vendor = self.scan[host]['vendor'][mac]
        else:
            vendor = "-"

        # Printing variables for users

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
        print('MAC address : %s\nVendor : %s' % (mac, vendor))

        # Storing all the desired variables in the hosts_result dict

        hosts_result['host_ip'] = host
        hosts_result['hostname'] = hostname
        hosts_result['state'] = state
        hosts_result['reason'] = reason
        hosts_result['mac'] = mac
        hosts_result['vendor(mac)'] = vendor

        # Returning dict
        # Final result is append in the scan_host function

        return hosts_result

    def get_os(self, host) -> list:
        # For each scanned host, this function retrieves information about the operating system
        # Depending on the accuracy, it will print it for the user and store the output data in a dict

        # Variables definition

        self.is_os_firewall = False
        os_matches = self.scan[host]['osmatch']
        os_result = {}
        os_list = []
        counter = 0

        print('\n----------\nOS match :\n----------')
        if len(os_matches) == 0:  # If no os is found via scan, dict os_result returns an error
            os_result['error'] = 'No match found for the requested OS'
            print(os_result['error'])
            os_list.append(os_result)
        else:
            for os_match in os_matches:  # for each os found, retrieving important information in local variables
                ct = 0
                os_copy = []
                counter += 1
                print("\nMatch n°%s\n" % counter)
                name = os_match['name']
                accuracy = os_match['accuracy']
                vendor = os_match['osclass'][0]['vendor']
                os_family = os_match['osclass'][0]['osfamily']
                os_gen = os_match['osclass'][0]['osgen']
                os_type = os_match['osclass'][0]['type']

                # Printing results

                print(f'Accuracy : {accuracy}\t OS name : {name}\t Vendor : {vendor}\t OS family : {os_family}\t '
                      f'OS gen : {os_gen}\t OS type : {os_type}')

                # Storing local variables in the os_result dict

                os_result['accuracy'] = accuracy
                os_result['os'] = name
                os_result['vendor'] = vendor
                os_result['os_family'] = os_family
                os_result['os_gen'] = os_gen
                os_result['os_type'] = os_type

                if int(accuracy) > 85:
                    if os_type == "firewall" and os_family != "embedded":  # If the OS is not embedded (phone os fi.)
                        ct += 1
                        self.is_os_firewall = True  # Boolean variable set to true for the scoring function
                        print(f"The scanned device has a {accuracy} % of being a firewall")

                        # Depending on the situation, the os_result dict is filled with information

                        os_result['firewall_os_accuracy'] = "Firewall accuracy percentage : " + accuracy + "%"
                    else:
                        os_result['firewall_os_accuracy'] = "No firewall OS detected via scan"
                else:
                    os_result['firewall_os_accuracy'] = "Accuracy not high enough to determine the OS's nature."

                if int(accuracy) > 90 and os_family != "embedded" and (vendor == "FreeBDS" or vendor == "OpenBSD"):
                    self.is_free_open = True

                # Depending on the number of OSes found with a firewall os_type, we will add more or less to the score

                if ct > 1:
                    self.score += self.coefficient_3 + ct
                elif ct == 1:
                    self.score += self.coefficient_3
                self.firewall_result['os_scan_number'] = ct  # Adding number of OSes with firewall type to the result
                self.firewall_result['os_name'] = vendor + f" ({os_family})"

                # To solve the mutability problem, copies of the list and dict are created to avoid overwriting existing
                # data in the original ones *copies point to a different memory slot and thus can be modified safely)

                os_result_copy = os_result.copy()
                os_copy.append(os_result_copy)
                os_list += os_copy
        return os_list

    def get_ports(self, host) -> list:
        # For each scanned host, this function retrieves information about the different scanned ports (open or closed)
        # The output is a list of dict containing ports information

        # Variables definition

        ports_result = {}
        ports_list = []
        print('\n----------------------\nProtocol information :\n----------------------')
        if not (self.scan[host].all_protocols()):  # If no protocols are found via scan, returning an error
            ports_result['error'] = 'No ports found for the requested device'
            print(ports_result['error'])
            ports_list.append(ports_result)
        for protocol in self.scan[host].all_protocols():
            ports = self.scan[host][protocol].keys()
            print('Protocol : %s\n' % protocol)
            for port in ports:  # for each port found for the scanned host, retrieving important info
                ports_copy = []  # Creating ports_copy list

                # Creating local variables

                state = self.scan[host]['tcp'][port]['state']
                reason = self.scan[host]['tcp'][port]['reason']
                service = self.scan[host]['tcp'][port]['name']
                product = self.scan[host]['tcp'][port]['product']
                version = self.scan[host]['tcp'][port]['version']

                self.host_protocol_list.append(service)  # Appending all ports numbers in a list for scoring function

                if state == "closed":
                    print('Port : %s\t \tState : closed' % port)
                elif state == "filtered":
                    print('Port : %s\t \tState : filtered' % port)
                else:
                    print(f'Port : {port}\t\tState : {state}\t Reason : {reason}\t Service : {service}\t\t\t '
                          f'Product : {product}\t\t\t Version : {version}')

                    # Storing the extracted values in the ports_result dict

                    ports_result['port'] = port
                    ports_result['state'] = state
                    ports_result['reason'] = reason
                    ports_result['service'] = service
                    ports_result['product'] = product
                    ports_result['version'] = version

                    # Storing ports_result in a dict copy, then appending it to a list which is added to our final list

                    ports_result_copy = ports_result.copy()
                    ports_copy.append(ports_result_copy)
                    ports_list += ports_copy
            print(self.host_protocol_list)
            # self.score_firewall(self.host_protocol_list)
            return ports_list

    def scan_host(self, host, os, ports, firewall_result, score, firewalk):
        # This function calls all different information about one host and appends it to a list of dictionnaries
        # (each dict in the list contains all the information of 1 host : host, os, ports, firewall result and score)
        self.scan_hosts.append({'host': host, 'os': os, 'ports': ports, 'firewall_result': firewall_result,
                                'score': score})

    def comparison_vendor(self, host) -> dict:
        # Compares the mac address of the scanned host to a list of vendors
        self.is_mac_vendor = False
        if self.scan[host]['status']['reason'] == "localhost-response":  # Excluding the scanning computer from result
            self.firewall_result = {'firewall_result': "Localhost computer (not part of the network)"}
        else:
            mac = self.scan[host]['addresses']['mac']
            mac_final = mac.split(":")[0] + ":" + mac.split(":")[1] + ":" + mac.split(":")[2]
            vendor_mac = conversion_xml_json("VendorList/vendorMacsFinal.xml", True)
            for i in range(len(vendor_mac['MacAddressVendorMappings']['VendorMapping'])):
                vendor = vendor_mac['MacAddressVendorMappings']['VendorMapping'][i]['@mac_prefix']
                if vendor == mac_final:  # If we find our hosts' mac prefix in the list
                    print(f"1 result found in database for MAC : {mac} \nCorresponds to vendor : "
                          f"{vendor_mac['MacAddressVendorMappings']['VendorMapping'][i]['@vendor_name']}")
                    self.is_mac_vendor = True
                    self.firewall_result['mac_vendor_found'] = self.is_mac_vendor
                    self.firewall_result['mac_vendor_result'] = f"MAC prefix : {mac} " \
                                                                "; Corresponds to vendor : " \
                                                                f"{vendor_mac['MacAddressVendorMappings']['VendorMapping'][i]['@vendor_name']} "
                    break
            if not self.is_mac_vendor:
                print(f'No match for requested MAC ({mac}) in the database')
                self.firewall_result['mac_vendor_result'] = f"No match for requested MAC ({mac}) in the database"
        return self.firewall_result

    def score_firewall(self, host, host_protocol_list) -> dict:
        # This function builds the overall score of each device by taking in account os, mac vendor and protocols
        # Score is added to the final_score dict
        web_server = ['https', 'http', 'ssh', 'telnet']
        mail_server = ['pop3', 'imap', 'smtp']
        other_services = ['snmp', 'dns', 'domain', 'omapi']
        # final_score = {}
        # actual_score = 0
        web_ct = 0
        mail_ct = 0
        other_ct = 0

        # For each prototype found for the scanned host, comparing it to 3 lists of services which are "classes"
        # The more different lists the prototype corresponds to, the stronger it is considered being a firewall

        for proto in host_protocol_list:
            print("Les protocoles : ", proto)
            if proto in web_server:
                self.firewall_protocol_list.append(proto)
                web_ct += 1
            elif proto in mail_server:
                self.firewall_protocol_list.append(proto)
                mail_ct += 1
            elif proto in other_services:
                self.firewall_protocol_list.append(proto)
                other_ct += 1
        print("La liste : ", self.firewall_protocol_list)

        # Utilisation de threads pour paralléliser le tout ?

        if web_ct != 0 and mail_ct != 0 and other_ct != 0 and len(host_protocol_list) > 2:
            self.firewalk_validation(host)
            self.score += self.coefficient_2 * (web_ct + mail_ct + other_ct)
            if self.is_os_firewall and self.is_mac_vendor:
                self.score += 13
            elif self.is_os_firewall:
                self.score += 8
            elif self.is_mac_vendor:
                self.score += 5
            elif (self.is_os_firewall or self.is_mac_vendor) and self.is_free_open:
                self.score += 11
            elif self.is_mac_vendor and self.is_os_firewall and self.is_free_open:
                self.score += 7
        elif ((web_ct != 0 and mail_ct != 0 and other_ct == 0) or (web_ct != 0 and other_ct != 0 and mail_ct == 0)
              or (mail_ct != 0 and other_ct != 0 and web_ct == 0)) and len(host_protocol_list) > 2:
            self.firewalk_validation(host)
            self.score += (web_ct + mail_ct + other_ct)
            if self.is_os_firewall and self.is_mac_vendor:
                self.score += 9
            elif self.is_os_firewall:
                self.score += 6
            elif self.is_mac_vendor:
                self.score += 3
                # Lancer script firewalk
                # self.firewalk_validation(host)
            elif (self.is_os_firewall or self.is_mac_vendor) and self.is_free_open:
                self.score += 7
            elif self.is_mac_vendor and self.is_os_firewall and self.is_free_open:
                self.score += 5
        else:
            self.firewalk_validation(host)
            self.score += self.coefficient_1 * (web_ct + mail_ct + other_ct)
            if self.is_os_firewall and self.is_mac_vendor:
                self.score += 7
            elif self.is_os_firewall:
                self.score += 4
            elif self.is_mac_vendor:
                self.score += 3
            elif (self.is_os_firewall or self.is_mac_vendor) and self.is_free_open:
                self.score += 5
            elif self.is_mac_vendor and self.is_os_firewall and self.is_free_open:
                self.score += 4
                # Script firewalk ?

        # Displaying score, adding it to the final_score dict

        print("Score : ", self.score)
        self.final_score['score'] = self.score

        # Depending on the score, we'll write the result as a string showing a chosen chance percentage of the scanned
        # device being a firewall

        if self.score <= 3:
            print("The scanned device is strongly NOT considered as a firewall with between 0% - 20% chance of being one.")
            self.final_score['final_result'] = 'The scanned device is strongly NOT considered as a firewall by ' \
                                               'scan, with between 0% - 20% chance of being one.'
        elif self.score in (4, 5):
            print("The scanned device may be a firewall with between 20% - 40% accuracy.")
            self.final_score['final_result'] = "The scanned device may be a firewall with between 20% - 40% accuracy."
        elif self.score in (6, 7):
            print("The scanned device may be a firewall with between 40% - 60% accuracy.")
            self.final_score['final_result'] = "The scanned device may be a firewall with between 40% - 60% accuracy."
        elif self.score in (8, 11):
            print("The scanned device may be a firewall with between 60% - 80% accuracy.")
            self.final_score['final_result'] = "The scanned device may be a firewall with between 60% - 80% accuracy."
        else:
            print("The scanned device has a great chance of being a firewall with 90+% accuracy.")
            self.final_score['final_result'] = 'The scanned device has a great chance of being a firewall with ' \
                                               '90+% accuracy'

        # Clearing both lists and score after scoring each host

        self.firewall_protocol_list.clear()
        self.host_protocol_list.clear()
        self.score = 0

        # Returning the final scoring result at the end of function

        return self.final_score

    def firewalk_validation(self, host) -> dict:
        # firewalk_scan = self.firewalk.scan(f'--script=firewalk --traceroute {host}')
        # print(firewalk_scan)
        os.system(f'nmap -oX output_firewalk/output.xml -F --script=firewalk --traceroute 10.1.20.1')
        self.firewalk = conversion_xml_json('output_firewalk/output.xml', True)
        firewalk_hop = self.firewalk['nmaprun']['trace']['hop']
        print(firewalk_hop)
        return self.firewalk


if __name__ == "__main__":
    print("\n---------Welcome to the nmap scanner tool for Python---------\n")
    address = str(input("Please enter a network (or unique address) to scan\n"))
    output = str(input("Choose the output file (JSON format)\n")) + ".json"
    print("\nScan in progress...\n")
    NMAPScan(address, output)
    # vendor_json = conversion_xml_json("vendorMacsFinal.xml", True)
    # print(vendor_json)
    print("\n-------------------------End of scan-------------------------")

    # todo : lancer script bash / shell depuis la fct pour lancer script nmap, l'exporter en XML puis le reprendre sur python et analyser les resultats
