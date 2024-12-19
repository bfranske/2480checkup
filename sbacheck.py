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
import stat
import tarfile

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
    try:
        # Get the file's status
        file_stat = os.stat(file_path)
        
        # Get the user ID and group ID
        uid = file_stat.st_uid
        gid = file_stat.st_gid
        
        # Get the username and group name
        user_name = pwd.getpwuid(uid).pw_name
        group_name = grp.getgrgid(gid).gr_name
        
        return user_name, group_name
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return False,False

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

def directoryExists(path):
    return os.path.isdir(path)

def fileContainsRegex(filePath, pattern):
    regex = re.compile(pattern)
    
    try:
        with open(filePath, 'r') as file:
            for line in file:
                if regex.search(line):
                    return True
        return False
    except FileNotFoundError:
        print(f"File not found: {filePath}")
        return False

def checkCommonFiles(sourceDir, targetDir, numFiles):
    #check if at least numFiles from the sourceDir exist in the targetDir
    try:
        sourceFiles = set(os.listdir(sourceDir))
        targetFiles = set(os.listdir(targetDir))
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return False
    
    commonFiles = sourceFiles.intersection(targetFiles)
    
    return len(commonFiles) >= numFiles

def verifyCopiedLines(sourceFile,targetFile,numLines):
    try:
        with open(sourceFile, 'r') as source_file:
            source_lines = source_file.readlines()
        
        with open(targetFile, 'r') as target_file:
            target_lines = target_file.readlines()
        
        # Check if at least 10 lines from /etc/passwd are in the backup file
        copied_lines_count = sum(1 for line in source_lines if line in target_lines)
        
        if copied_lines_count >= numLines:
            return True
        else:
            return False
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return False

def verifyRecursiveOwnership(directory, username):
    if not os.path.exists(directory):
        return None

    try:
        # Get the UID of the specified username
        user_uid = pwd.getpwnam(username).pw_uid
        
        # Walk through the directory
        for root, dirs, files in os.walk(directory):
            # Check the ownership of the directory
            if os.stat(root).st_uid != user_uid:
                return False
            
            # Check the ownership of each file, skip links
            for name in files:
                file_path = os.path.join(root, name)
                if os.path.islink(file_path):
                    pass
                else:
                    if os.stat(file_path).st_uid != user_uid:
                        return False
            
            # Check the ownership of each subdirectory
            for name in dirs:
                dir_path = os.path.join(root, name)
                if os.stat(dir_path).st_uid != user_uid:
                    return False
        
        return True
    except KeyError:
        print(f"User '{username}' does not exist.")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def checkPermissions(directory, permissionList):
    #check how many files in directory do not match permissionList, skip links
    #permissionList like ['-rw-------', '-rwx------']
    if not os.path.exists(directory):
        return False

    non_compliant_files = 0
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.islink(file_path):
                pass
            else:
                mode = os.stat(file_path).st_mode
                permissions = stat.filemode(mode)
                if permissions not in permissionList:
                    non_compliant_files += 1
    
    return non_compliant_files

def checkFilesInTar(tar_path, dir_path, min_files=10):
    # Open the tar file
    try:
        with tarfile.open(tar_path, 'r:gz') as tar:
            # Get the list of files in the tar archive
            tar_files = [os.path.normpath(f) for f in tar.getnames()]
            print(tar_files)
            
            # Get the list of files in the specified directory
            dir_files = [os.path.normpath(os.path.relpath(os.path.join(dir_path, f), dir_path)) for f in os.listdir(dir_path)]
            print(dir_files)
            
            # Count how many files from the directory are in the tar archive
            count = sum(1 for f in dir_files if f in tar_files)
            
            # Check if the count is at least min_files
            return count >= min_files
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return False

def checkSoftLink(source, target):
    try:
        # Check if the source is a symbolic link
        if os.path.islink(source):
            # Get the path the symbolic link points to
            link_target = os.readlink(source)
            print(link_target)
            # Check if it matches the target path
            if link_target == target:
                return True
        return False
    except FileNotFoundError as e:
        print(f"Error: {e}")
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
itcfinalDirectory = directoryExists('/home/examuser/itcfinal')
dmesgInKernmsg = fileContainsRegex('/home/examuser/itcfinal/kernmsg.txt', r'^\[\s*\d+\.\d+\]\s+ Command line: BOOT_IMAGE=.* root=.*')
checkEtcBackup = checkCommonFiles('/etc/', '/home/examuser/backups/orig-config/', 10)
checkPasswdBackup = verifyCopiedLines('/etc/passwd','/home/examuser/backups/system-users', 10)
checkBackupOwnership = verifyRecursiveOwnership('/home/examuser/backups', 'linuxgeek')
checkBackupPermissions = checkPermissions('/home/examuser/backups', ['-rw-------', '-rwx------'])
checkLogTar = checkFilesInTar('/home/examuser/itcfinal/systemlogs.tar.gz','/var/log',10)
backupSoftlink = checkSoftLink('/home/linuxgeek/itcfinal-backups','/home/examuser/backups')

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
print("------------------------------")
print("Part 4:")
print("------------------------------")
print(f"itcfinal directory exists: {itcfinalDirectory}")
print(f"kernmsg.txt contains dmesg output: {dmesgInKernmsg}")
print(f"At least 10 files from /etc/ are in backups/orig-config/: {checkEtcBackup}")
print(f"Password file was backed up and renamed: {checkPasswdBackup}")
print(f"Recursive ownership of /home/examuser/backups is linuxgeek: {checkBackupOwnership}")
print(f"Number of non-compliant permissions in backup directory: {checkBackupPermissions}")
print(f"At least 10 files from /var/log in systemlogs.tar.gz: {checkLogTar}")
print(f"itcfinal-backups soft link in place: {backupSoftlink}")



#test=json.loads(subprocess.run(["ip", "-j", "addr", "show"], capture_output=True).stdout)
#print(test)