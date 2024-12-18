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
                else:
                    ipData[intName].update(ipv4 = None)
                    ipData[intName].update(ipv4prefix = None)
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

def checkSudo(username):
    sudoPermissions = subprocess.run(['sudo', '-l', '-U', username], text=True, capture_output=True)
    pattern = r"(is not allowed to run sudo|unknown user)"
    if re.search(pattern, sudoPermissions.stdout) or re.search(pattern, sudoPermissions.stderr):
        return False
    else:
        return True

ipDetails = getInterfaceDetails()
systemSetupDate = getRootFSCreationDate()
hostname = subprocess.run(['hostname'], capture_output=True).stdout.decode('utf-8')
domainname = systemDomainName()
rootPasswordTest = testPassword('root','r00tp@ss')
examPasswordTest = testPassword('examuser','GoodLuck')
examSudoTest = checkSudo('examuser')
linuxPasswordTest = testPassword('linuxgeek','linuxi$fun!')
linuxSudoTest = checkSudo('linuxgeek')

print("------------------------------")
print("System Report:")
print("------------------------------")
print(f"The system was installed on: {systemSetupDate}")
print("------------------------------")
print("Part 2:")
print("------------------------------")
print(f"ens192 is {ipDetails['ens192']['state']} with IP Address: {ipDetails['ens192']['ipv4']}/{ipDetails['ens192']['ipv4prefix']}")
print(f"The system host name is {hostname}")
print(f"The system domain name is {domainname}")
print(f"The root user account has the right password: {rootPasswordTest}")
print("------------------------------")
print("Part 3:")
print("------------------------------")
print(f"The examuser user account has the right password: {examPasswordTest}")
print(f"The examuser user account has sudo: {examSudoTest}")
print(f"The linuxgeek user account has the right password: {linuxPasswordTest}")
print(f"The linuxgeek user account has sudo: {linuxSudoTest}")

#test=json.loads(subprocess.run(["ip", "-j", "addr", "show"], capture_output=True).stdout)
#print(test)