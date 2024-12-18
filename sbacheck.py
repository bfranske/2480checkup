#!/usr/bin/python3
# ITC2480 skills exam checkup script
import subprocess
import json
import re
from datetime import datetime
import socket
import pam

def getInterfaceDetails():
    ipData = {}
    allIntData = json.loads(subprocess.run(["ip", "-j", "addr", "show"], text=True, capture_output=True).stdout)
    for iface in allIntData:
        if iface.get('ifname'):
            intName = iface.get('ifname')
            ipData[intName] = {}
            for addr_info in iface.get('addr_info', []):
                if addr_info.get('family') == 'inet':
                    ipData[intName].update(ipv4 = addr_info.get('local'))
                    ipData[intName].update(ipv4prefix = str(addr_info.get('prefixlen')))
            ipData[intName].update(state = iface.get('operstate'))
    return(ipData)

def getRootFSCreationDate():
    partition = '/dev/sda1'
    tuneOutput = subprocess.run(['tune2fs', '-l', partition], text=True, capture_output=True).stdout
    pattern = r"^Filesystem created:\s+(.*)$"
    match = re.search(pattern, tuneOutput, re.MULTILINE)
    if match:
        creation_time = match.group(1)
        date_format = "%a %b %d %H:%M:%S %Y"
        date_obj = datetime.strptime(creation_time, date_format)
        #print("Filesystem created:", date_obj)
        return date_obj
    return None

def systemDomainName():
    try:
        # Get the fully qualified domain name
        fqdn = socket.getfqdn()
        return fqdn
    except Exception as e:
        return str(e)

def testPassword(username, password):
    p = pam.pam()
    return p.authenticate(username, password, service='login', resetcreds=True)

ipDetails = getInterfaceDetails()
systemSetupDate = getRootFSCreationDate()
hostname = subprocess.run(['hostname'], capture_output=True).stdout.decode('utf-8')
domainname = systemDomainName()
print(testPassword('root','r00tp@ssa'))

#test=json.loads(subprocess.run(["ip", "-j", "addr", "show"], capture_output=True).stdout)
#print(test)