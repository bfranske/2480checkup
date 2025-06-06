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
    except NotADirectoryError:
        print(f"Directory not found: {filePath}")
        return False

def checkCommonFiles(sourceDir, targetDir, numFiles):
    #check if at least numFiles from the sourceDir exist in the targetDir
    try:
        sourceFiles = set(os.listdir(sourceDir))
        targetFiles = set(os.listdir(targetDir))
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return False
    except NotADirectoryError as e:
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
    except NotADirectoryError as e:
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
    except NotADirectoryError as e:
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
    except NotADirectoryError as e:
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
    try:
        with open(filePath, 'w') as file:
            file.write(php_code)
    except FileNotFoundError as e:
        return str(e)
    
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
    try:
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
    except:
        return f"Error: Unable to access site", f"Error: Unable to access site"

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

    try:
        # Check the timer schedule
        timer_info = subprocess.check_output(['systemctl', 'cat', timer_name]).decode()
        on_calendar_line = next((line for line in timer_info.splitlines() if 'OnCalendar=' in line), None)
        on_unit_active_sec_line = next((line for line in timer_info.splitlines() if 'OnUnitActiveSec=' in line), None)
        
        if on_calendar_line:
            actual_schedule = on_calendar_line.split('=')[1].strip()
            if schedule not in actual_schedule:
                return False, f"Timer {timer_name} does not match the specified schedule. It is set to {actual_schedule}."
        elif on_unit_active_sec_line:
            actual_interval = on_unit_active_sec_line.split('=')[1].strip()
            note = f"Timer {timer_name} is using OnUnitActiveSec with an interval of {actual_interval}."
        else:
            return False, f"Timer {timer_name} does not have an OnCalendar or OnUnitActiveSec schedule."

        # Check the service command, user, and group
        service_info = subprocess.check_output(['systemctl', 'cat', service_name]).decode()
        if command not in service_info:
            return False, f"Service {service_name} is not running the specified command."
        if f"User={user}" not in service_info:
            return False, f"Service {service_name} is not running as the specified user."
        if f"Group={group}" not in service_info:
            return False, f"Service {service_name} is not running as the specified group."

        return True, note if 'note' in locals() else "All checks passed."

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
    # Check if the file exists
    if not os.path.exists(filePath):
        return f"Error: '{filePath}' does not exist."

    # Get the hash of the first numlines of the systemd journal
    journal_output = subprocess.run(f'journalctl --no-pager | head -n {numlines} | sha256sum', capture_output=True, text=True, shell=True)
    journal_lines = journal_output.stdout

    # Get the hash of the first numlines of the file
    file_output = subprocess.run(f'cat {filePath} | head -n {numlines} | sha256sum', capture_output=True, text=True, shell=True)
    file_lines = file_output.stdout

    # Compare the lines
    if journal_lines == file_lines:
        return "Lines Match"
    else:
        return "No Match"
    
def getParitionSizes(device):
    # Run the lsblk command to get partition information in JSON format
    result = subprocess.run(['lsblk', '-o', 'NAME,SIZE', '-J', device], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')

    # Parse the JSON output
    data = json.loads(output)

    # Initialize an empty dictionary to store partition sizes
    partition_sizes = {}

    # Iterate over the block devices and their children (partitions)
    for block_device in data['blockdevices']:
        for partition in block_device.get('children', []):
            partition_name = partition['name']
            partition_sizes[partition_name] = partition['size']

    return partition_sizes

def getFilesystemTypes(device):
    # Run the lsblk command and get the output in JSON format
    result = subprocess.run(['lsblk', '-o', 'NAME,FSTYPE,SIZE', '-J', device], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')
    
    # Parse the JSON output
    data = json.loads(output)
    
    # Initialize an empty dictionary to store the filesystem info
    fs_info = {}
    
    # Iterate over each block device
    for block_device in data['blockdevices']:
        # Iterate over each partition of the device
        for partition in block_device.get('children', []):
            # Convert size to GB and round to the nearest hundredth
            size_str = partition['size']
            
            # Add the partition number, filesystem type, and size to the dictionary
            fs_info[partition['name']] = {
                'fstype': partition['fstype'],
                'size_gb': size_str
            }
    
    return fs_info

def getMountPoints(device):
    # Run the lsblk command and get the output in JSON format
    result = subprocess.run(['lsblk', '-o', 'NAME,MOUNTPOINT', '-J', device], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')
    
    # Parse the JSON output
    data = json.loads(output)
    
    # Initialize an empty dictionary to store the filesystem info
    fs_info = {}
    
    # Iterate over each block device
    for block_device in data['blockdevices']:
        # Iterate over each partition of the device
        for partition in block_device.get('children', []):
            # Convert size to GB and round to the nearest hundredth
            mountpoint = partition['mountpoint']
            
            # Add the partition number, filesystem type, and size to the dictionary
            fs_info[partition['name']] = {
                'mountpoint': mountpoint
            }
    
    return fs_info

def getDeviceAutomounts(blockdevice):
    # Run lsblk with JSON output
    result = subprocess.run(['lsblk', '-o', 'NAME,UUID', '--json', blockdevice], capture_output=True, text=True)
    lsblk_output = json.loads(result.stdout)
    
    # Parse the lsblk output to get partition names and UUIDs
    partitions = {}
    for device in lsblk_output['blockdevices']:
        if 'children' in device:
            for child in device['children']:
                if 'uuid' in child and child['uuid']:
                    partitions[child['name']] = child['uuid']
    
    # Read the /etc/fstab file
    with open('/etc/fstab', 'r') as fstab_file:
        fstab_lines = fstab_file.readlines()
    
    # Check if UUID or partition name is set to automount and get the mount point
    mountpoints = {}
    for line in fstab_lines:
        if not line.startswith('#') and line.strip():
            parts = line.split()
            if len(parts) >= 2:
                device, mountpoint = parts[0], parts[1]
                if device.startswith('UUID='):
                    uuid = device.split('=')[1]
                    for partition, part_uuid in partitions.items():
                        if part_uuid == uuid:
                            mountpoints[partition] = mountpoint
                else:
                    #check for old style fstab using the /dev/sdXX instead of UUID
                    device_name = device.replace('/dev/', '')
                    if device_name in partitions:
                        mountpoints[device] = mountpoint
    
    return mountpoints

def verifyCachingNameserver(bindConfigFile='/etc/bind/named.conf.options', forwarderIP='172.17.50.1'):
    try:
        with open(bindConfigFile, 'r') as file:
            config = file.read()
       
        # Check if the forwarder IP is set correctly and not commented out
        forwarder_pattern = r'forwarders\s*{[^}]*\n\s*' + re.escape(forwarderIP) + r';'
        forwarder = re.search(forwarder_pattern, config)
        if not forwarder:
            return f"Forwarder IP {forwarderIP} is not set correctly or is commented out."
        return "Correct forwarder."
    
    except FileNotFoundError:
        return f"Configuration file {bindConfigFile} not found."
    except NotADirectoryError:
        return f"Configuration directory {bindConfigFile} not found."
    except Exception as e:
        return f"An error occurred: {e}"

def getResolvedDNSServers(interface):
    try:
        # Run the resolvectl status command and capture the output
        result = subprocess.run(['resolvectl', 'status', interface], capture_output=True, text=True, check=True)
        
        # Extract the line containing the current DNS server
        for line in result.stdout.split('\n'):
            if 'Current DNS Server' in line:
                # Extract and return the DNS server address
                return line.split()[-1]
        
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None

def getResolvConfServers():
    nameserver_ips = []
    try:
        with open('/etc/resolv.conf', 'r') as file:
            for line in file:
                if line.startswith('nameserver'):
                    nameserver_ips.append(line.split()[1])
    except FileNotFoundError:
        print("The /etc/resolv.conf file does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")
    
    return nameserver_ips

def getDNSRecord(domain, record_type='A', dns_server=None):
    try:
        # Prepare the dig command with the optional DNS server and record type
        command = ['dig', '+short', domain, record_type]
        if dns_server:
            command.insert(1, f'@{dns_server}')
        
        # Run the dig command
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout.strip().split('\n')
        
        # Filter out any empty strings from the output
        records = [line for line in output if line]
        
        return records
    except subprocess.CalledProcessError as e:
        return f"Error running dig command: {e}"
    except FileNotFoundError as e:
        return f"Error running dig command: {e}"

def checkDockerContainerStatus(image_name):
    # Get the JSON output from the docker ps -a command
    result = subprocess.run(['docker', 'ps', '-a', '--format', '{{json .}}'], capture_output=True, text=True)
    containers = result.stdout.strip().split('\n')
    
    # Parse the JSON output
    container_data = [json.loads(container) for container in containers]
    
    # Check the status of the given image
    running = False
    has_run = False
    container_id = None
    exact_image_name = None
    
    for container in container_data:
        if container['Image'].startswith(image_name):
            has_run = True
            container_id = container['ID']
            exact_image_name = container['Image']
            if container['State'] == 'running':
                running = True
                break
    
    return running, has_run, container_id, exact_image_name

def getDockerContainerInfo(container_id):
    # Run docker inspect command and get the output
    result = subprocess.run(['docker', 'inspect', container_id], stdout=subprocess.PIPE)
    container_info = json.loads(result.stdout)[0]

    # Extract the required information
    container_name = container_info['Name'].strip('/')
    ports = container_info['NetworkSettings']['Ports']
    auto_remove = container_info['HostConfig']['AutoRemove']
    restart_policy = container_info['HostConfig']['RestartPolicy']['Name']

    # Format the ports information
    bridged_ports = {port: details[0]['HostPort'] for port, details in ports.items() if details}

    # Determine if the container will restart automatically unless stopped
    auto_restart = restart_policy == 'unless-stopped'

    return {
        'container_name': container_name,
        'bridged_ports': bridged_ports,
        'auto_remove': auto_remove,
        'auto_restart': auto_restart
    }

def getKeaConfig(subnet_value):
    config_path = '/etc/kea/kea-dhcp4.conf'
    
    try:
        with open(config_path, 'r') as file:
            config = json.load(file)
    except json.decoder.JSONDecodeError as e:
        return {'error': e}
    except FileNotFoundError as e:
        return {'error': e}
    
    address_pool = None
    default_gateway = None
    dns_servers = None
    
    # Find the subnet configuration
    for subnet in config['Dhcp4']['subnet4']:
        if subnet['subnet'] == subnet_value:
            address_pool = subnet['pools'][0]['pool']
            if 'option-data' in subnet:
                for option in subnet['option-data']:
                    if option['name'] == 'routers':
                        default_gateway = option['data']
                    elif option['name'] == 'domain-name-servers':
                        dns_servers = option['data']
            break
    
    # If not found in the subnet, check global options
    try:
        if not default_gateway or not dns_servers:
            for option in config['Dhcp4']['option-data']:
                if option['name'] == 'routers' and not default_gateway:
                    default_gateway = option['data']
                elif option['name'] == 'domain-name-servers' and not dns_servers:
                    dns_servers = option['data']
    except KeyError:
        #no big deal, we were just giving a second chance anyway
        pass
    
    return {
        'address_pool': address_pool,
        'default_gateway': default_gateway,
        'dns_servers': dns_servers
    }

def getFirewalldZones():
    try:
        # Run the firewall-cmd command to get the list of zones
        result = subprocess.run(['firewall-cmd', '--get-zones'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check if the command was successful
        if result.returncode == 0:
            # Split the output into a list of zones
            zones = result.stdout.strip().split()
            return zones
        else:
            print(f"Error: {result.stderr}")
            return []
    except Exception as e:
        print(f"An exception occurred: {e}")
        return []
    
def getFirewalldZoneRules(zone):
    try:
        # Run the firewall-cmd command to get the --list-all output for the specified zone
        result = subprocess.run(['firewall-cmd', '--zone', zone, '--list-all'], capture_output=True, text=True)
        
        # Check if the command was successful
        if result.returncode != 0:
            return result.stderr
    except FileNotFoundError as e:
        return str(e)
    
    # Split the output into lines
    lines = result.stdout.splitlines()
    
    # Initialize an empty dictionary to store the parsed data
    parsed_data = {}
    
    # Iterate over each line and parse it into the dictionary
    for line in lines:
        if ':' in line:  # Only process lines with a colon
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            if ' ' in value:
                value = value.split()
            parsed_data[key] = value
    
    return parsed_data

def listFirewalldPolicies():
    try:
        # Run the firewall-cmd command to get the list of policies
        result = subprocess.run(['firewall-cmd', '--get-policies'], capture_output=True, text=True, check=True)
        # Split the result by newline to get each policy as a list item
        policies = result.stdout.strip().split()
        return policies
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        return []
    except FileNotFoundError as e:
        print(f"An error occurred: {e}")
        return []
    
def getFirewalldPolicy(policy_name):
    result = {
        'ingress_zones': [],
        'egress_zones': [],
        'target': None
    }
    
    try:
        # Get the policy information using firewall-cmd
        policy_info = subprocess.check_output(['firewall-cmd', '--info-policy', policy_name], text=True)
        
        for line in policy_info.split('\n'):
            line = line.strip()
            if line.startswith('ingress-zones:'):
                result['ingress_zones'] = line.split(':')[1].strip().split()
            elif line.startswith('egress-zones:'):
                result['egress_zones'] = line.split(':')[1].strip().split()
            elif line.startswith('target:'):
                result['target'] = line.split(':')[1].strip()
    
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving policy information: {e}")
    except FileNotFoundError as e:
        print(f"An error occurred: {e}")
    
    return result

def checkScriptDetails(path, filenameNoExtension):
    # Check if the file with .sh or .py extension exists
    sh_file = os.path.join(path, filenameNoExtension + '.sh')
    py_file = os.path.join(path, filenameNoExtension + '.py')
    
    if os.path.isfile(sh_file):
        full_path = sh_file
    elif os.path.isfile(py_file):
        full_path = py_file
    else:
        return {"exists": False, "message": "File with .sh or .py extension does not exist"}

    # Get file details
    file_stat = os.stat(full_path)
    user = pwd.getpwuid(file_stat.st_uid).pw_name
    group = grp.getgrgid(file_stat.st_gid).gr_name
    permissions = stat.filemode(file_stat.st_mode)

    # Return the details in a dictionary
    return {
        "exists": True,
        "full_path": full_path,
        "user": user,
        "group": group,
        "permissions": permissions
    }

def readFileAsString(filePath):
    with open(filePath, 'r') as file:
        contents = file.read()
    return contents

def doExamCheck():
    report = ''
    report +="------------------------------\n"
    report +="System Report:\n"
    report +="------------------------------\n"
    systemSetupDate = getRootFSCreationDate()
    report +=f"The system was installed on: {systemSetupDate}\n"
    report +="------------------------------\n"
    report +="Part 2: Basic Installation\n"
    report +="------------------------------\n"
    ipDetails = getInterfaceDetails()
    report +=f"ens192 is {ipDetails['ens192']['state']} with IP Address: {ipDetails['ens192']['ipv4']}/{ipDetails['ens192']['ipv4prefix']}\n"
    hostname = subprocess.run(['hostname'], capture_output=True).stdout.decode('utf-8').strip()
    report +=f"The system host name is {hostname}\n"
    podID = hostname.split('-')[-1]
    report +=f"The POD ID Letter is {podID}\n"
    domainname = systemDomainName()
    report +=f"The system domain name is {domainname}\n"
    rootPasswordTest = testPassword('root','r00tp@ss')
    report +=f"The root user account has the right password: {rootPasswordTest}\n"
    report +="------------------------------\n"
    report +="Part 3: Users, Groups, Software\n"
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
    lastTenLinesCommand = checkBASHHistory('examuser', 'tail -10 /var/log/dpkg.log > /home/examuser/recent-packages') or checkBASHHistory('examuser', 'tail -n 10 /var/log/dpkg.log > /home/examuser/recent-packages')
    report +=f"Did examuser create a file of recent packages with 10 lines: {lastTenLinesCommand}\n"
    recentPackagesUser,recentPackagesGroup = getFileOwnership('/home/examuser/recent-packages')
    report +=f"recent-packages file owner is: {recentPackagesUser}\n"
    report +=f"recent-packages file group owner is: {recentPackagesGroup}\n"
    sectionThreePackages = isPackageInstalled('python3') and isPackageInstalled('curl') and isPackageInstalled('locate') and isPackageInstalled('python3-requests')
    report +=f"Section 3 required packages are installed: {sectionThreePackages}\n"
    report +="------------------------------\n"
    report +="Part 4: System Navigation and File Utilities\n"
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
    backupSoftlink = checkSoftLink('/home/linuxgeek/itcfinal-backups','/home/examuser/backups/') or checkSoftLink('/home/linuxgeek/itcfinal-backups','/home/examuser/backups')
    report +=f"itcfinal-backups soft link in place: {backupSoftlink}\n"
    report +="------------------------------\n"
    report +="Part 5: Webserver\n"
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
    resolvedPackage = isPackageInstalled('systemd-resolved')
    report +=f"systemd-resolved installed: {resolvedPackage}\n"
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
    report +="Part 6: System Administration\n"
    report +="------------------------------\n"
    updatedbCronjob = checkCronSchedule('updatedb')
    report +=f"Root is running updatedb on cron schedule: {updatedbCronjob}\n"
    touchTimerCorrect,touchTimerMessage = verifySystemdTimer('makefile.timer', 'makefile.service', '*:0/10:0', 'touch /home/examuser/itcfinal/timertest', 'examuser', 'students')
    report +=f"Checking systemd timer: {touchTimerMessage}\n"
    touchTimerLastMod = getLastModifiedDate('/home/examuser/itcfinal/timertest')
    report +=f"Systemd Timer File Last Modified: {touchTimerLastMod}\n"
    journalCopy = verifyJournalInFile(100,'/home/examuser/itcfinal/biglog')
    report +=f"System Journal Copied to biglog (first 100 lines at least): {journalCopy}\n"
    sdbPartitions = getParitionSizes('/dev/sdb')
    report +=f"SDB Partitions: {sdbPartitions}\n"
    sdbFilesystems = getFilesystemTypes('/dev/sdb')
    report +=f"SDB Filesystems: {sdbFilesystems}\n"
    sdbMounts = getMountPoints('/dev/sdb')
    report +=f"SDB Mounts: {sdbMounts}\n"
    sdbAutoMounts = getDeviceAutomounts('/dev/sdb')
    report +=f"SDB Auto Mounts: {sdbAutoMounts}\n"
    report +="------------------------------\n"
    report +="Part 7: Nameserver\n"
    report +="------------------------------\n"
    dnsPackages = isPackageInstalled('bind9') and isPackageInstalled('dnsutils')
    report +=f"BIND and dnsutils are installed: {dnsPackages}\n"
    cachingNameserver = verifyCachingNameserver('/etc/bind/named.conf.options', '172.17.50.1')
    report +=f"BIND Caching Nameserver: {cachingNameserver}\n"
    resolvedPackage = isPackageInstalled('systemd-resolved')
    report +=f"systemd-resolved installed: {resolvedPackage}\n"
    if resolvedPackage:
        systemDNSServers = getResolvedDNSServers('ens192')
        report +=f"System DNS Servers via resolved: {systemDNSServers}\n"
    else:
        systemDNSServers = getResolvConfServers()
        report +=f"System DNS Servers via resolv.conf: {systemDNSServers}\n"
    recordType = 'A'
    lookupDomain = 'local.sba-'+podID+'.itc2480.campus.ihitc.net'
    dnsServer = '127.0.0.1'
    dnsRecord = getDNSRecord(lookupDomain,recordType,dnsServer)
    report +=f"{recordType} records for {lookupDomain}: {dnsRecord}\n"
    recordType = 'A'
    lookupDomain = 'sba-'+podID+'.itc2480.campus.ihitc.net'
    dnsServer = '127.0.0.1'
    dnsRecord = getDNSRecord(lookupDomain,recordType,dnsServer)
    report +=f"{recordType} records for {lookupDomain}: {dnsRecord}\n"
    recordType = 'A'
    lookupDomain = 'mailserver.sba-'+podID+'.itc2480.campus.ihitc.net'
    dnsServer = '127.0.0.1'
    dnsRecord = getDNSRecord(lookupDomain,recordType,dnsServer)
    report +=f"{recordType} records for {lookupDomain}: {dnsRecord}\n"
    recordType = 'CNAME'
    lookupDomain = 'www.sba-'+podID+'.itc2480.campus.ihitc.net'
    dnsServer = '127.0.0.1'
    dnsRecord = getDNSRecord(lookupDomain,recordType,dnsServer)
    report +=f"{recordType} records for {lookupDomain}: {dnsRecord}\n"
    recordType = 'MX'
    lookupDomain = 'sba-'+podID+'.itc2480.campus.ihitc.net'
    dnsServer = '127.0.0.1'
    dnsRecord = getDNSRecord(lookupDomain,recordType,dnsServer)
    report +=f"{recordType} records for {lookupDomain}: {dnsRecord}\n"
    recordType = 'TXT'
    lookupDomain = 'sba-'+podID+'.itc2480.campus.ihitc.net'
    dnsServer = '127.0.0.1'
    dnsRecord = getDNSRecord(lookupDomain,recordType,dnsServer)
    report +=f"{recordType} records for {lookupDomain}: {dnsRecord}\n"
    report +="------------------------------\n"
    report +="Part 8: Containers\n"
    report +="------------------------------\n"
    dockerPackage = isPackageInstalled('docker-ce')
    report +=f"docker-ce installed: {dockerPackage}\n"
    if dockerPackage:
        dockerHelloWorldRunning,dockerHelloWorldHasRun,dockerHelloWorldID, docketHelloWorldImage = checkDockerContainerStatus('hello-world')
        report +=f"docker image {docketHelloWorldImage} has run: {dockerHelloWorldHasRun}\n"
        dockerNginxRunning,dockerNginxHasRun,dockerNginxID, dockerNginxImage = checkDockerContainerStatus('nginx')
        report +=f"docker image {dockerNginxImage} has run: {dockerNginxHasRun}\n"
        report +=f"docker image {dockerNginxImage} is running: {dockerNginxRunning}\n"
        if dockerNginxID:
            dockerNginxDetails = getDockerContainerInfo(dockerNginxID)
            report +=f"docker Nginx details: {dockerNginxDetails}\n"
    report +="------------------------------\n"
    report +="Part 9: Networking, Firewall, and Security\n"
    report +="------------------------------\n"
    ipDetails = getInterfaceDetails()
    report +=f"ens224 is {ipDetails['ens224']['state']} with IP Address: {ipDetails['ens224']['ipv4']}/{ipDetails['ens224']['ipv4prefix']}\n"
    keaPackage = isPackageInstalled('kea-dhcp4-server')
    report +=f"Kea DHCP Server installed: {keaPackage}\n"
    keaStatus=checkSystemdServiceStatus('kea-dhcp4-server')
    report +=f"The '{keaStatus['service']}' service is enabled: {keaStatus['enabledStatus']}\n"
    report +=f"The '{keaStatus['service']}' service is running: {keaStatus['runningStatus']}\n"
    keaConfig = getKeaConfig('192.168.123.0/24')
    report +=f"The kea config for 192.168.123.0/24: {keaConfig}\n"
    firewalldPackage = isPackageInstalled('firewalld')
    report +=f"firewalld installed: {firewalldPackage}\n"
    firewalldStatus=checkSystemdServiceStatus('firewalld')
    report +=f"The '{firewalldStatus['service']}' service is enabled: {firewalldStatus['enabledStatus']}\n"
    report +=f"The '{firewalldStatus['service']}' service is running: {firewalldStatus['runningStatus']}\n"
    firewalldZones = getFirewalldZones()
    report +=f"firewalld zones: {firewalldZones}\n"
    firewalldPublicZoneRules = getFirewalldZoneRules('public')
    report +=f"firewalld public zone: {firewalldPublicZoneRules}\n"
    firewalldPrivateZoneRules = getFirewalldZoneRules('private')
    report +=f"firewalld private zone: {firewalldPrivateZoneRules}\n"
    firewalldPolicies = listFirewalldPolicies()
    report +=f"firewalld policies: {firewalldPolicies}\n"
    for policy in firewalldPolicies:
        policyDetails = getFirewalldPolicy(policy)
        report +=f"firewalld policy {policy}: {policyDetails}\n"
    report +="------------------------------\n"
    report +="Part 10: Scripting\n"
    report +="------------------------------\n"
    scriptInfo = checkScriptDetails('/home/examuser/','myscript')
    if scriptInfo['exists']:
        report +=f"script path: {scriptInfo['full_path']}\n"
        report +=f"script user: {scriptInfo['user']}\n"
        report +=f"script group: {scriptInfo['group']}\n"
        report +=f"script permissions: {scriptInfo['permissions']}\n"
        scriptFile = readFileAsString(scriptInfo['full_path'])
        report +="-------------BEGIN SCRIPT---------------\n"
        report +=scriptFile
        report +="\n"
        report +="-------------END SCRIPT-----------------\n"
    else:
        report +=f"No script file found.\n"
    report +="------------------------------\n"
    return report

#print(doExamCheck())
file_path = "/root/sbaresult.txt"
text_to_write = doExamCheck()

with open(file_path, "w") as file:
    file.write(text_to_write)