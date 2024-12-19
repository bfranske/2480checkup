#!/usr/bin/python3
# ITC2480 skills exam checkup script
import subprocess
import json
import re
from datetime import datetime
import time
import socket
import pam
import grp
import pwd
import os
import stat
import tarfile
import requests
import html

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
                if os.path.islink(dir_path):
                    pass
                else:
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
            
            # Get the list of files in the specified directory
            dir_files = []
            for root, _, files in os.walk(dir_path):
                for f in files:
                    relative_path = os.path.relpath(os.path.join(root, f), '/')
                    full_path = str(os.path.join(root, f))
                    dir_files.append(os.path.normpath(relative_path))
                    dir_files.append(os.path.normpath(full_path))
            
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
            # Check if it matches the target path
            if link_target == target:
                return True
        return False
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return False

def getSystemdNetworkConfig(interface):
    config_dir = '/etc/systemd/network/'
    config_files = [f for f in os.listdir(config_dir) if f.endswith('.network')]
    
    ipv4_pattern = re.compile(r'Address=(\S+)/.*')
    ipv4mask_pattern = re.compile(r'Address=\S+/(\d+)')
    ipv4gateway_pattern = re.compile(r'Gateway=(\S+)')
    dns_pattern = re.compile(r'DNS=(\S+)')
    
    network_config = {
        'ipv4address': None,
        'ipv4mask': None,
        'ipv4gateway': None,
        'dns': []
    }
    
    for config_file in config_files:
        with open(os.path.join(config_dir, config_file), 'r') as file:
            content = file.read()
            if f'[Match]\nName={interface}' in content:
                ipv4_match = ipv4_pattern.search(content)
                ipv4mask_match = ipv4mask_pattern.search(content)
                ipv4gateway_match = ipv4gateway_pattern.search(content)
                dns_matches = dns_pattern.findall(content)
                
                if ipv4_match:
                    network_config['ipv4address'] = ipv4_match.group(1)
                if ipv4mask_match:
                    network_config['ipv4mask'] = ipv4mask_match.group(1)
                if ipv4gateway_match:
                    network_config['ipv4gateway'] = ipv4gateway_match.group(1)
                if dns_matches:
                    network_config['dns'] = dns_matches
                
                break
    
    return network_config

def checkSystemdServiceStatus(serviceName):
    try:
        # Check if the service is enabled
        enabled_result = subprocess.run(['systemctl', 'is-enabled', serviceName], capture_output=True, text=True)
        # Check if the service is running
        running_result = subprocess.run(['systemctl', 'is-active', serviceName], capture_output=True, text=True)
        
        # Determine enabled status
        if enabled_result.returncode == 0:
            enabled_status = True
        elif enabled_result.returncode == 1:
            enabled_status = False
        else:
            #Could not determine the enabled status of the service
            enabled_status = None
        # Determine the running status
        if running_result.returncode == 0:
            running_status = True
        elif running_result.returncode == 3:
            running_status = False
        else:
            running_status = None

        return {'service': serviceName, 'enabledStatus': enabled_status, 'runningStatus': running_status}

    except Exception as e:
        return f"An error occurred: {e}"

def checkWebserver(url):
    try:
        response = requests.head(url, timeout=5)
        if response.status_code == 200:
            server = response.headers.get('Server')
            if server:
                return server
            else:
                return f"Could not determine the web server software for {url}"
        else:
            return None
    except requests.RequestException:
        return None

def checkPHPVersion(filePath, url):
    # PHP code to display the version of PHP running on the system
    php_code = "<?php\nphpinfo();\n?>"
    
    # Write the PHP code to the file
    with open(filePath, 'w') as file:
        file.write(php_code)
    
    os.chmod(filePath, 0o755)

    try:
        response = requests.get(url)
        if response.status_code == 200:
            content = response.text
            start = content.find('<h1 class="p">PHP Version ') + len('<h1 class="p">PHP Version ')
            end = content.find('</h1>', start)
            if start != -1 and end != -1:
                php_version = content[start:end]
                return php_version
            else:
                return None
        else:
            return f"Failed to retrieve the page. Status code: {response.status_code}"
    except Exception as e:
        return str(e)
    
def getWordpressTitles(url):
    response = requests.get(url)
    
    # Check if the response status code is 200 OK
    if response.status_code != 200:
        return f"Error: {response.status_code}", f"Error: {response.status_code}"
    
    html_content = response.text
    
    # Extract the site title using regex
    site_title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
    site_title = html.unescape(site_title_match.group(1)) if site_title_match else 'No site title found'
    
    # Extract the title of the most recent blog post using regex
    recent_post_match = re.search(r'<h2.*?wp-block-post-title.*?<a.*?>(.*?)</a>', html_content, re.IGNORECASE | re.DOTALL)
    recent_post_title = html.unescape(recent_post_match.group(1).strip()) if recent_post_match else 'No recent post found'
    
    return site_title, recent_post_title

def checkCronSchedule(command):
    try:
        # Read the root user's crontab
        result = subprocess.run(['crontab', '-l', '-u', 'root'], capture_output=True, text=True)
        
        if result.returncode != 0:
            return "Failed to read root's crontab, may not exist."
        
        # Check if the specified command is in the crontab and return its schedule
        cronjobs = result.stdout.splitlines()
        for job in cronjobs:
            if command in job:
                schedule = job.split(command)[0].strip()
                return schedule
        
        return f"No cron job found for command"
    
    except Exception as e:
        return f"An error occurred: {e}"

def verifySystemdTimer(timer_name, service_name, schedule, command, user, group):
    try:
        # Check if the timer is active
        timer_status = subprocess.check_output(['systemctl', 'is-enabled', timer_name]).decode().strip()
        if timer_status != 'enabled':
            return False, f"Timer {timer_name} is not enabled."
    except subprocess.CalledProcessError:
            return False, f"Timer {timer_name} is not enabled."

        # Check the timer schedule
    try:
        timer_info = subprocess.check_output(['systemctl', 'cat', timer_name]).decode()
        on_calendar_line = next((line for line in timer_info.splitlines() if 'OnCalendar=' in line), None)
        if on_calendar_line:
            actual_schedule = on_calendar_line.split('=')[1].strip()
            if schedule not in actual_schedule:
                return False, f"Timer {timer_name} does not match the specified schedule. It is set to {actual_schedule}."
        else:
            return False, f"Timer {timer_name} does not have an OnCalendar schedule."

        # Check the service command, user, and group
        service_info = subprocess.check_output(['systemctl', 'cat', service_name]).decode()
        if command not in service_info:
            return False, f"Service {service_name} is not running the specified command."
        if f"User={user}" not in service_info:
            return False, f"Service {service_name} is not running as the specified user."
        if f"Group={group}" not in service_info:
            return False, f"Service {service_name} is not running as the specified group."

        return True, "All checks passed."

    except subprocess.CalledProcessError as e:
        return False, str(e)

def getLastModifiedDate(file_path):
    # Check if the file exists
    if not os.path.exists(file_path):
        return f"The file '{file_path}' does not exist."
    
    # Get the last modified time
    last_modified_time = os.path.getmtime(file_path)
    
    # Convert the time to a readable format
    last_modified_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_modified_time))
    
    return last_modified_date

def verifyJournalInFile(numlines,filePath):
    # Get the first 100 lines of the systemd journal
    journal_output = subprocess.run(['journalctl', '--no-pager', '|', 'head', '-100'], capture_output=True, text=True)
    journal_lines = journal_output.stdout.splitlines()[:numlines]

    # Check if the file exists
    if not os.path.exists(filePath):
        return f"Error: '{filePath}' does not exist."

    # Read the first 100 lines of the file
    with open(filePath, 'r') as file:
        file_lines = [next(file) for _ in range(numlines)]

    # Compare the lines
    if journal_lines == file_lines:
        return "Lines Match"
    else:
        return "No Match"

def doExamCheck():
    report = ''
    report +="------------------------------\n"
    report +="System Report:\n"
    report +="------------------------------\n"
    systemSetupDate = getRootFSCreationDate()
    report +=f"The system was installed on: {systemSetupDate}\n"
    report +="------------------------------\n"
    report +="Part 2:\n"
    report +="------------------------------\n"
    ipDetails = getInterfaceDetails()
    report +=f"ens192 is {ipDetails['ens192']['state']} with IP Address: {ipDetails['ens192']['ipv4']}/{ipDetails['ens192']['ipv4prefix']}\n"
    hostname = subprocess.run(['hostname'], capture_output=True).stdout.decode('utf-8')
    report +=f"The system host name is {hostname}\n"
    domainname = systemDomainName()
    report +=f"The system domain name is {domainname}\n"
    rootPasswordTest = testPassword('root','r00tp@ss')
    report +=f"The root user account has the right password: {rootPasswordTest}\n"
    report +="------------------------------\n"
    report +="Part 3:\n"
    report +="------------------------------\n"
    examPasswordTest = testPassword('examuser','GoodLuck')
    report +=f"The examuser user account has the right password: {examPasswordTest}\n"
    examSudoTest = checkSudo('examuser')
    report +=f"The examuser user account has sudo: {examSudoTest}\n"
    linuxPasswordTest = testPassword('linuxgeek','linuxi$fun!')
    report +=f"The linuxgeek user account has the right password: {linuxPasswordTest}\n"
    linuxSudoTest = checkSudo('linuxgeek')
    report +=f"The linuxgeek user account has sudo: {linuxSudoTest}\n"
    studentGroupTest = doesGroupExist('students')
    report +=f"The student group exists: {studentGroupTest}\n"
    if studentGroupTest:
        studentGroupMembers = grp.getgrnam('students').gr_mem
    else:
        studentGroupMembers = None
    report +=f"student group members: {studentGroupMembers}\n"
    lastTenLinesCommand = checkBASHHistory('examuser', 'tail -10 /var/log/dpkg.log > /home/linuxgeek/recent-packages') or checkBASHHistory('examuser', 'tail -n 10 /var/log/dpkg.log > /home/linuxgeek/recent-packages')
    report +=f"Did examuser create a file of recent packages with 10 lines: {lastTenLinesCommand}\n"
    recentPackagesUser,recentPackagesGroup = getFileOwnership('/home/linuxgeek/recent-packages')
    report +=f"recent-packages file owner is: {recentPackagesUser}\n"
    report +=f"recent-packages file group owner is: {recentPackagesGroup}\n"
    sectionThreePackages = isPackageInstalled('python3') and isPackageInstalled('curl') and isPackageInstalled('locate') and isPackageInstalled('python3-requests')
    report +=f"Section 3 required packages are installed: {sectionThreePackages}\n"
    report +="------------------------------\n"
    report +="Part 4:\n"
    report +="------------------------------\n"
    itcfinalDirectory = directoryExists('/home/examuser/itcfinal')
    report +=f"itcfinal directory exists: {itcfinalDirectory}\n"
    dmesgInKernmsg = fileContainsRegex('/home/examuser/itcfinal/kernmsg.txt', r'^\[\s*\d+\.\d+\]\s+Command line: BOOT_IMAGE=.* root=.*')
    report +=f"kernmsg.txt contains dmesg output: {dmesgInKernmsg}\n"
    checkEtcBackup = checkCommonFiles('/etc/', '/home/examuser/backups/orig-config/', 10)
    report +=f"At least 10 files from /etc/ are in backups/orig-config/: {checkEtcBackup}\n"
    checkPasswdBackup = verifyCopiedLines('/etc/passwd','/home/examuser/backups/system-users', 10)
    report +=f"Password file was backed up and renamed: {checkPasswdBackup}\n"
    checkBackupOwnership = verifyRecursiveOwnership('/home/examuser/backups', 'linuxgeek')
    report +=f"Recursive ownership of /home/examuser/backups is linuxgeek: {checkBackupOwnership}\n"
    checkBackupPermissions = checkPermissions('/home/examuser/backups', ['-rw-------', '-rwx------'])
    report +=f"Number of non-compliant permissions in backup directory: {checkBackupPermissions}\n"
    checkLogTar = checkFilesInTar('/home/examuser/itcfinal/systemlogs.tar.gz','/var/log',10)
    report +=f"At least 10 files from /var/log in systemlogs.tar.gz: {checkLogTar}\n"
    backupSoftlink = checkSoftLink('/home/linuxgeek/itcfinal-backups','/home/examuser/backups/')
    report +=f"itcfinal-backups soft link in place: {backupSoftlink}\n"
    report +="------------------------------\n"
    report +="Part 5:\n"
    report +="------------------------------\n"
    ens192StaticIP = getSystemdNetworkConfig('ens192')
    report +=f"Static ens192 IPv4 Address is: {ens192StaticIP['ipv4address']}/{ens192StaticIP['ipv4mask']}\n"
    report +=f"Active ens192 IPv4 Address is: {ipDetails['ens192']['ipv4']}/{ipDetails['ens192']['ipv4prefix']}\n"
    networkdStatus=checkSystemdServiceStatus('systemd-networkd')
    report +=f"The newer service '{networkdStatus['service']}' is enabled: {networkdStatus['enabledStatus']}\n"
    report +=f"The newer service '{networkdStatus['service']}' is running: {networkdStatus['runningStatus']}\n"
    networkingStatus=checkSystemdServiceStatus('networking')
    report +=f"The older service '{networkingStatus['service']}' is enabled: {networkingStatus['enabledStatus']}\n"
    report +=f"The older service '{networkingStatus['service']}' is running: {networkingStatus['runningStatus']}\n"
    basicURL = 'http://'+ipDetails['ens192']['ipv4']
    webserver=checkWebserver(basicURL)
    report +=f"The webserver running at {basicURL} is: {webserver}\n"
    phpVersion=checkPHPVersion('/var/www/html/testphpver.php',basicURL+'/testphpver.php')
    report +=f"The php version running is: {phpVersion}\n"
    mariaDBPackage = isPackageInstalled('mariadb-server')
    report +=f"MariaDB Server is installed: {mariaDBPackage}\n"
    phpmysqlPackage = isPackageInstalled('php-mysql')
    report +=f"PHP-MySQL is installed: {phpmysqlPackage}\n"
    wordpressPackage = isPackageInstalled('wordpress')
    report +=f"Wordpress DEB Package is installed: {wordpressPackage}\n"
    wordpressSiteTitle,wordpressPostTitle = getWordpressTitles(basicURL+'/blog')
    report +=f"Wordpress Site Title: {wordpressSiteTitle}\n"
    report +=f"Wordpress Post Title: {wordpressPostTitle}\n"
    report +="------------------------------\n"
    report +="Part 6:\n"
    report +="------------------------------\n"
    updatedbCronjob = checkCronSchedule('updatedb')
    report +=f"Root is running updatedb on cron schedule: {updatedbCronjob}\n"
    touchTimerCorrect,touchTimerMessage = verifySystemdTimer('makefile.timer', 'makefile.service', '*:0/10:0', 'touch /home/examuser/itcfinal/timertest', 'examuser', 'students')
    report +=f"Checking systemd timer: {touchTimerMessage}\n"
    touchTimerLastMod = getLastModifiedDate('/home/examuser/itcfinal/timertest')
    report +=f"Systemd Timer File Last Modified: {touchTimerLastMod}\n"
    journalCopy = verifyJournalInFile(100,'/home/examuser/itcfinal/biglog')
    report +=f"System Journal Copied to biglog (first 100 lines at least): {journalCopy}\n"
    return report

print(doExamCheck())