#!/usr/bin/python3
# ITC2480 skills exam checkup script
import subprocess
import json
import re
from datetime import datetime
import socket
import pam
import grp
import pwd
import os

def getInterfaceDetails():
    ipData = {}
    allIntData = json.loads(subprocess.run(["ip", "-j", "addr", "show"], text=True, capture_output=True).stdout)
    for iface in allIntData:
        if iface.get('ifname'):
            intName = iface.get('ifname')
            ipData[intName] = {}
            ipData[intName].update(ipv4 = None)
            ipData[intName].update(ipv4prefix = None)
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

def checkSudo(username):
    sudoPermissions = subprocess.run(['sudo', '-l', '-U', username], text=True, capture_output=True)
    pattern = r"(is not allowed to run sudo|unknown user)"
    if re.search(pattern, sudoPermissions.stdout) or re.search(pattern, sudoPermissions.stderr):
        return False
    else:
        return True

def doesGroupExist(groupname):
    try:
        grp.getgrnam(groupname)
        return True
    except KeyError:
        return False

def isUserInGroup(username, groupname):
    try:
        group_info = grp.getgrnam(groupname)
        user_info = pwd.getpwnam(username)
        return username in group_info.gr_mem or user_info.pw_gid == group_info.gr_gid
    except KeyError:
        return False

def checkBASHHistory(user, command):
    # Path to the user's bash history file
    history_file = f"/home/{user}/.bash_history"
    
    # Check if the history file exists
    if not os.path.exists(history_file):
        return None
    
    # Read the history file and check for the command
    with open(history_file, 'r') as file:
        history = file.readlines()
    
    # Create a regex pattern to match the command with optional characters before or after
    pattern = re.compile(rf".*{re.escape(command)}.*")
    
    # Check if the command is in the history
    for line in history:
        if pattern.match(line):
            return True
    return False

def getFileOwnership(file_path):
    # Get the file's status
    file_stat = os.stat(file_path)
    
    # Get the user ID and group ID
    uid = file_stat.st_uid
    gid = file_stat.st_gid
    
    # Get the username and group name
    user_name = pwd.getpwuid(uid).pw_name
    group_name = grp.getgrgid(gid).gr_name
    
    return user_name, group_name

def isPackageInstalled(packageName):
    try:
        # Run the dpkg -s command
        result = subprocess.run(['dpkg', '-s', packageName], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Check the return code
        if result.returncode == 0:
            return True
        else:
            return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

ipDetails = getInterfaceDetails()
systemSetupDate = getRootFSCreationDate()
hostname = subprocess.run(['hostname'], capture_output=True).stdout.decode('utf-8')
domainname = systemDomainName()
rootPasswordTest = testPassword('root','r00tp@ss')
examPasswordTest = testPassword('examuser','GoodLuck')
examSudoTest = checkSudo('examuser')
linuxPasswordTest = testPassword('linuxgeek','linuxi$fun!')
linuxSudoTest = checkSudo('linuxgeek')
studentGroupTest = doesGroupExist('students')
if studentGroupTest:
    studentGroupMembers = grp.getgrnam('students').gr_mem
else:
    studentGroupMembers = None
lastTenLinesCommand = checkBASHHistory('examuser', 'tail -10 /var/log/dpkg.log > /home/linuxgeek/recent-packages') or checkBASHHistory('examuser', 'tail -n 10 /var/log/dpkg.log > /home/linuxgeek/recent-packages')
recentPackagesUser,recentPackagesGroup = getFileOwnership('/home/linuxgeek/recent-packages')
sectionThreePackages = isPackageInstalled('python3') and isPackageInstalled('curl') and isPackageInstalled('locate') and isPackageInstalled('python3-requests')

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
print(f"The student group exists: {studentGroupTest}")
print(f"student group members: {studentGroupMembers}")
print(f"Did examuser create a file of recent packages with 10 lines: {lastTenLinesCommand}")
print(f"recent-packages file owner is: {recentPackagesUser}")
print(f"recent-packages file group owner is: {recentPackagesGroup}")
print(f"Section 3 required packages are installed: {sectionThreePackages}")


#test=json.loads(subprocess.run(["ip", "-j", "addr", "show"], capture_output=True).stdout)
#print(test)