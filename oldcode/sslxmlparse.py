#!/bin/python3

import xml.etree.ElementTree as ET
import csv

context = {
    # Vuln Tables
    # Add k/v when new vuln incorporated
    'deprecated':{},
    'ssc':{},
    'expc':{},
    'wkhsig':{},
}


# Sort findings by category, host
# XML in, context dicts out
def sorter():
    # dicts of vulns. Host:Details
    # context = {'10.10.10.10:1337':[TLSv1.0, TLSv1.1]}
    for i in range(0, len('a')):                          # sys.argv
        tree = ET.parse('ssl.xml')  # sys.argv[i]
        root = tree.getroot()
        # check ssltest to get data
        for child in root:
            # collect ip
            ip_address = str(child.get('sniname')) + ':' + str(child.get('port'))
            print('ip collected')

            i = 0
            for protocol in child.iter('protocol'):
                """
                Deprecated SSL/TLS Check
                6 protocols tested, the first 4 are BAD
                want 'enabled' == 0 for protocols 0-4
                add host to list if !0
                if host in list, append protocol only to key value.
                """
                print('testing protocol ' + str(i) + ' with enable code ' + protocol.attrib['enabled'])
                if int(protocol.attrib['enabled']) == 1 and i < 4:
                    print('enabled protocol found at ' + str(i))
                    if ip_address not in context['deprecated']:
                        context['deprecated'][ip_address] = [protocol.attrib['type'].upper() + 'v' + protocol.attrib[
                            'version']]
                    else:
                        context['deprecated'][ip_address].append(
                            protocol.attrib['type'].upper() + 'v' + protocol.attrib['version'])
                i += 1
            
            if child.find('certificates'):      # Apparently section omits sometimes
                for cert in child.find('certificates').iter('certificate'):
                    """
                    SSL Certificate Checks:
                    - Self-Signed
                    - Expired (uses sys time to determine)
                    
                    Iterates through each cert in the <certificates/> section
                    and determines various things about them :)
                    """
                    if cert.find('self-signed').text == 'true':
                        if ip_address not in context['ssc']:
                            context['ssc'][ip_address] = cert.find('subject').text
                        else:
                            context['ssc'][ip_address].append(cert.find('subject').text)

                    if cert.find('expired').text == 'true':
                        if ip_address not in context['expc']:
                            context['expc'][ip_address] = str(cert.find('subject').text) + ' ' + cert.find('not-valid-after').text
                        else:
                            context['expc'][ip_address].append(cert.find('subject').text + ' ' + cert.find('not-valid-after').text)

            

        return context

def export(context):
    with open("sslexport.csv", 'w', newline='') as exportfile:
        csv_writer = csv.writer(exportfile)
        csv_writer.writerow(['Category','IP:Po','Proto'])
        for category, hosts in context.items():
            for host, protocols in hosts.items():
                csv_writer.writerow([category, host, ' '.join(protocols)])


sorter()
print(context)
export(context)
