import json
import nmap
import xmltodict


class JSONEncode(json.JSONEncoder):
    def serialize_sets(self, obj):
        if isinstance(obj, set):
            return list(obj)

        return json.JSONEncoder.default(self, obj)


def conversion_xml_json(xml_file, xml_attribs):
    with open(xml_file, "rb") as fw:
        xml_to_dict = xmltodict.parse(fw, xml_attribs=xml_attribs)
        json_obj = json.dumps(xml_to_dict, default=JSONEncode, indent=4)
        json_serializable = json.loads(json_obj)
        print(json_serializable)

        with open("file2.json", "w", encoding='utf-8') as file:
            json.dump(json_serializable, file, ensure_ascii=False, indent=4)
        fw.close()

    return json_serializable


def output_json(output_data, output_file):
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(output_data, file, indent=4)


class NMAPScan:
    def __init__(self, ipaddress, output):
        self.scan = nmap.PortScanner()
        q = self.scan.scan(hosts=ipaddress, arguments='-sV -O -sC')
        print(q)
        self.hosts = self.scan.all_hosts()
        self.firewall_result = {}
        self.scan_hosts = []

        print("Hosts found : %s" % len(self.hosts))
        print("\n--------------SCANNING HOSTS--------------")

        for host in self.hosts:
            self.scan_host(self.get_host(host), self.get_os(host), self.get_ports(host), self.comparison_vendor(host))
        output_json(self.scan_hosts, output)

    def get_host(self, host) -> dict:

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

        # Variables prints + storing in dict

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

        hosts_result['host_ip'] = host
        hosts_result['hostname'] = hostname
        hosts_result['state'] = state
        hosts_result['reason'] = reason
        hosts_result['mac'] = mac
        hosts_result['vendor(mac)'] = vendor

        # Returning dict
        # Final result is append in scan_host fct

        return hosts_result

    def get_os(self, host) -> list:
        os_matches = self.scan[host]['osmatch']
        os_result = {}
        os_list = []
        counter = 0
        print('\n----------\nOS match :\n----------')
        if len(os_matches) == 0:
            os_result['error'] = 'No match found for the requested OS'
            print(os_result['error'])
            os_list.append(os_result)
        else:
            for os_match in os_matches:  # for each os found, retrieving important infos
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

                # print('Accuracy : %s\t OS name : %s\t Vendor : %s\t OS family : %s\t OS gen : %s' %
                #       (accuracy, name, vendor, os_family, os_gen))
                print(f'Accuracy : {accuracy}\t OS name : {name}\t Vendor : {vendor}\t OS family : {os_family}\t '
                      f'OS gen : {os_gen}\t OS type : {os_type}')

                # Storing results in a dict, then appending it to a list (if accuracy > 85%)

                os_result['accuracy'] = accuracy
                os_result['os'] = name
                os_result['vendor'] = vendor
                os_result['os_family'] = os_family
                os_result['os_gen'] = os_gen
                os_result['os_type'] = os_type
                os_result_copy = os_result.copy()
                os_copy.append(os_result_copy)

                if int(accuracy) > 85:
                    os_list += os_copy
                    if not os_type:
                        self.firewall_result['firewall_os_accuracy'] = "No OS type found via scan"
                    if os_type == "firewall":
                        print(f"The scanned device has a {accuracy} % of being a firewall")
                        self.firewall_result['firewall_os_accuracy'] = accuracy + "%"
                    else:
                        self.firewall_result['firewall_os_accuracy'] = "No firewall OS detected via scan"
                else:
                    print("Accuracy not high enough to determine the OS's nature.")
        return os_list

    def get_ports(self, host) -> list:
        ports_result = {}
        ports_list = []
        print('\n----------------------\nProtocol information :\n----------------------')
        if not (self.scan[host].all_protocols()):
            ports_result['error'] = 'No ports found for the requested device'
            print(ports_result['error'])
            ports_list.append(ports_result)
        for protocol in self.scan[host].all_protocols():
            ports = self.scan[host][protocol].keys()
            print('Protocol : %s\n' % protocol)
            for port in ports:  # for each port found for the scanned host, retrieving important infos
                ports_copy = []
                state = self.scan[host]['tcp'][port]['state']
                reason = self.scan[host]['tcp'][port]['reason']
                service = self.scan[host]['tcp'][port]['name']
                product = self.scan[host]['tcp'][port]['product']
                version = self.scan[host]['tcp'][port]['version']
                if state == "closed":
                    print('Port : %s\t \tState : closed' % port)
                elif state == "filtered":
                    print('Port : %s\t \tState : filtered' % port)
                else:
                    print(f'Port : {port}\t\tState : {state}\t Reason : {reason}\t Service : {service}\t\t\t '
                          f'Product : {product}\t\t\t Version : {version}')

                    # Storing the extracted values in a dict ports_result

                    ports_result['port'] = port
                    ports_result['state'] = state
                    ports_result['reason'] = reason
                    ports_result['service'] = service
                    ports_result['product'] = product
                    ports_result['version'] = version

                    # Storing ports_results in a dict copy, then appending it to a list that is added at the end of the
                    # wanted list

                    ports_result_copy = ports_result.copy()
                    ports_copy.append(ports_result_copy)
                    ports_list += ports_copy

            return ports_list

    def scan_host(self, host, os, ports, firewall_result):
        self.scan_hosts.append({'host': host, 'os': os, 'ports': ports, 'firewall_result': firewall_result})

    def comparison_vendor(self, host):
        found = False
        if self.scan[host]['status']['reason'] == "localhost-response":
            self.firewall_result = {'firewall_result': "Localhost computer"}
        else:
            mac = self.scan[host]['addresses']['mac']
            mac_final = mac.split(":")[0] + ":" + mac.split(":")[1] + ":" + mac.split(":")[2]
            vendor_mac = conversion_xml_json("vendorMacsFinal.xml", True)
            for i in range(len(vendor_mac['MacAddressVendorMappings']['VendorMapping'])):
                vendor = vendor_mac['MacAddressVendorMappings']['VendorMapping'][i]['@mac_prefix']
                if vendor == mac_final:
                    print(f"1 result found in database for MAC : {mac} \nCorresponds to vendor : "
                          f"{vendor_mac['MacAddressVendorMappings']['VendorMapping'][i]['@vendor_name']}")
                    found = True
                    self.firewall_result['firewall_result'] = f"1 result found in database for MAC : {mac}" \
                                                              " ; Corresponds to vendor : " \
                                                              f"{vendor_mac['MacAddressVendorMappings']['VendorMapping'][i]['@vendor_name']} "
                    break
            if not found:
                print(f'No match for requested MAC ({mac}) in the database')
                self.firewall_result = {'firewall_result': f"No match for requested MAC ({mac}) in the database"}
        return self.firewall_result


if __name__ == "__main__":
    print("\n---------Welcome to the nmap scanner tool for Python---------\n")
    address = str(input("Please enter a network (or unique address) to scan\n"))
    output = str(input("Choose the output file (JSON format)\n")) + ".json"
    print("\nScan in progress...\n")
    NMAPScan(address, output)
    # vendor_json = conversion_xml_json("vendorMacsFinal.xml", True)
    # print(vendor_json)
    print("\n-------------------------End of scan-------------------------")
